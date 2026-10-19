package dns

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	"tailscale.com/tailcfg"
	"tailscale.com/util/set"
)

// TestUpdateRecordsDoesNotBlockShutdown ensures updateRecords does not park
// forever on the update channel during shutdown. The send must release the
// write lock first and abort on closeCh, otherwise the Run goroutine leaks and
// holds the lock indefinitely when no consumer is draining the channel.
func TestUpdateRecordsDoesNotBlockShutdown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "extra.json")
	require.NoError(t, os.WriteFile(path,
		[]byte(`[{"name":"a.example.com","type":"A","value":"100.64.0.1"}]`), 0o600))

	er, err := NewExtraRecordsManager(path)
	require.NoError(t, err)

	defer er.watcher.Close()

	// Change the file so updateRecords passes the unchanged-hash guard and
	// reaches the send with no consumer draining UpdateCh.
	require.NoError(t, os.WriteFile(path,
		[]byte(`[{"name":"b.example.com","type":"A","value":"100.64.0.2"}]`), 0o600))

	done := make(chan struct{})

	go func() {
		er.updateRecords()
		close(done)
	}()

	er.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("updateRecords parked on a blocking send and did not return after Close")
	}
}

// TestWaitUntilPathExistsReturnsOnClose ensures Close unblocks the
// Remove/Rename retry. A missing extra-records file must not pin Run
// for the 15-minute backoff budget after shutdown.
func TestWaitUntilPathExistsReturnsOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "extra.json")
	require.NoError(t, os.WriteFile(path,
		[]byte(`[{"name":"a.example.com","type":"A","value":"100.64.0.1"}]`), 0o600))

	er, err := NewExtraRecordsManager(path)
	require.NoError(t, err)

	require.NoError(t, os.Remove(path))

	done := make(chan error, 1)

	go func() {
		done <- er.waitUntilPathExists()
	}()

	er.Close()

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("waitUntilPathExists did not return after Close while the extra-records file was missing")
	}
}

func TestExtraRecordsUpdateDifferential(t *testing.T) {
	const (
		a = `{"name":"a.example.com","type":"A","value":"100.64.0.1"}`
		b = `{"name":"b.example.com","type":"AAAA","value":"fd7a:115c:a1e0::2"}`
	)

	for _, format := range []struct {
		ext        string
		valid      string
		changed    string
		duplicates string
		malformed  string
	}{
		{"json", "[" + a + "]", "[" + b + "," + a + "]", "[" + b + "," + b + "," + a + "]", `[{"name":`},
		{"hujson", "[/* initial */" + a + ",]", "[// changed\n" + b + "," + a + ",]", "[" + b + "," + b + "," + a + ",]", `[/* rewritten */{"name":123},]`},
		{"yaml", "- name: a.example.com\n  value: 100.64.0.1\n", "- &record\n  name: b.example.com\n  value: fd7a:115c:a1e0::2\n", "- &record\n  name: b.example.com\n  value: fd7a:115c:a1e0::2\n- *record\n", "- name: ["},
		{"yml", "- name: a.example.com\n", "- name: b.example.com\n", "- name: b.example.com\n- name: b.example.com\n", "- name: ["},
	} {
		t.Run(format.ext, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "extra."+format.ext)
			require.NoError(t, os.WriteFile(path, []byte(format.valid), 0o600))
			initial, initialHash, err := readExtraRecordsFromPathOriginal(path)
			require.NoError(t, err)

			original := &ExtraRecordsMan{
				path:    path,
				records: set.SetOf(initial),
				hash:    initialHash,
				updateCh: make(
					chan []tailcfg.DNSRecord,
					2,
				),
				closeCh: make(chan struct{}),
			}
			candidate, err := NewExtraRecordsManager(path)
			require.NoError(t, err)
			t.Cleanup(candidate.Close)
			candidate.updateCh = make(chan []tailcfg.DNSRecord, 2)
			require.Equal(t, original.hash, candidate.hash)
			require.ElementsMatch(t, original.Records(), candidate.Records())

			for _, step := range []struct {
				name   string
				body   string
				notify int
			}{
				{"same", format.valid, 0},
				{"changed", format.changed, 1},
				{"malformed", format.malformed, 0},
				{"malformed-again", format.malformed, 0},
				{"empty", "", 0},
				{"null", "null", 0},
				{"empty-array", "[]", 1},
				{"same-empty-array", "[]", 0},
				{"duplicates", format.duplicates, 1},
				{"same-duplicates", format.duplicates, 0},
				{"same-records-new-bytes", format.duplicates + "\n", 1},
				{"missing", "", 0},
				{"directory", "", 0},
				{"recovered", format.valid, 1},
			} {
				t.Run(step.name, func(t *testing.T) {
					switch step.name {
					case "missing":
						require.NoError(t, os.Remove(path))
					case "directory":
						require.NoError(t, os.Mkdir(path, 0o700))
					case "recovered":
						require.NoError(t, os.Remove(path))
						require.NoError(t, os.WriteFile(path, []byte(step.body), 0o600))
					default:
						require.NoError(t, os.WriteFile(path, []byte(step.body), 0o600))
					}

					want, wantHash, wantErr := readExtraRecordsFromPathOriginal(path)
					got, gotHash, gotErr := readExtraRecordsFromPath(path, nil)
					require.Equal(t, want, got)
					require.Equal(t, wantHash, gotHash)
					require.Equal(t, fmt.Sprint(wantErr), fmt.Sprint(gotErr))

					previousHash := candidate.hash

					got, gotHash, gotErr = readExtraRecordsFromPath(path, &previousHash)
					if wantErr == nil && wantHash == previousHash {
						require.Nil(t, got)
					} else {
						require.Equal(t, want, got)
					}

					require.Equal(t, wantHash, gotHash)
					require.Equal(t, fmt.Sprint(wantErr), fmt.Sprint(gotErr))

					original.updateRecordsOriginal()
					candidate.updateRecords()
					require.Equal(t, original.hash, candidate.hash)

					if step.notify == 0 {
						require.Equal(t, previousHash, candidate.hash)
					} else {
						require.Equal(
							t,
							sha256.Sum256([]byte(step.body)),
							candidate.hash,
						)
					}

					oldRecords, newRecords := original.Records(), candidate.Records()
					require.Equal(t, oldRecords == nil, newRecords == nil)
					require.ElementsMatch(t, oldRecords, newRecords)
					require.Len(t, original.updateCh, step.notify)
					require.Len(t, candidate.updateCh, step.notify)

					for range step.notify {
						oldUpdate, newUpdate := <-original.UpdateCh(), <-candidate.UpdateCh()
						require.Equal(t, oldUpdate == nil, newUpdate == nil)
						require.ElementsMatch(t, oldUpdate, newUpdate)
						require.ElementsMatch(t, newRecords, newUpdate)

						if len(newUpdate) > 0 {
							newUpdate[0].Name = "changed by consumer"

							require.ElementsMatch(t, oldRecords, candidate.Records())
						}
					}

					if len(newRecords) > 0 {
						newRecords[0].Name = "changed by reader"

						require.ElementsMatch(t, oldRecords, candidate.Records())
					}
				})
			}
		})
	}
}

func TestExtraRecordsReaderIgnoredAndRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		ext  string
		body string
	}{
		{"empty", "json", ""},
		{"null", "json", "null"},
		{"empty-array", "json", "[]"},
		{"yaml-null", "yaml", "~"},
		{"yaml-comment", "yaml", "# no records\n"},
		{"hujson-null", "hujson", "/* no records */ null"},
		{"hujson-comment", "hujson", "// no records\n"},
		{"json-comment", "json", "// invalid\n[]"},
		{"hujson-malformed", "hujson", "[/* incomplete"},
		{"unknown-extension", "txt", "[]"},
		{"unknown-extension-empty", "txt", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "extra."+tc.ext)
			require.NoError(t, os.WriteFile(path, []byte(tc.body), 0o600))
			want, wantHash, wantErr := readExtraRecordsFromPathOriginal(path)

			var acceptedHash [32]byte
			for range 2 {
				for _, previousHash := range []*[32]byte{nil, &acceptedHash} {
					got, gotHash, gotErr := readExtraRecordsFromPath(path, previousHash)
					require.Equal(t, want, got)
					require.Equal(t, wantHash, gotHash)
					require.Equal(t, fmt.Sprint(wantErr), fmt.Sprint(gotErr))
				}
			}

			manager, err := NewExtraRecordsManager(path)
			if wantErr != nil {
				require.EqualError(
					t,
					err,
					"reading extra records from path: "+wantErr.Error(),
				)
				require.Nil(t, manager)

				return
			}

			require.NoError(t, err)
			t.Cleanup(manager.Close)
			require.Equal(t, wantHash, manager.hash)
			require.ElementsMatch(t, set.SetOf(want).Slice(), manager.Records())
			manager.updateCh = make(chan []tailcfg.DNSRecord, 1)
			manager.updateRecords()
			require.Empty(t, manager.updateCh)
		})
	}
}

func TestExtraRecordsConcurrentReadUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "extra.hujson")
	manager := &ExtraRecordsMan{
		path: path, updateCh: make(chan []tailcfg.DNSRecord, 16),
		closeCh: make(chan struct{}),
	}

	for round := range 4 {
		body := fmt.Sprintf(`[/* round %d */{"name":"%d.example.com"},]`, round, round)
		require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

		start := make(chan struct{})

		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				<-start

				for range 16 {
					manager.updateRecords()
					_ = manager.Records()
				}
			})
		}

		close(start)
		wg.Wait()
		require.Len(t, manager.updateCh, 1)
		require.Equal(t, sha256.Sum256([]byte(body)), manager.hash)
		require.Equal(
			t,
			[]tailcfg.DNSRecord{{Name: fmt.Sprintf("%d.example.com", round)}},
			<-manager.UpdateCh(),
		)
		require.Equal(
			t,
			[]tailcfg.DNSRecord{{Name: fmt.Sprintf("%d.example.com", round)}},
			manager.Records(),
		)
	}
}

func BenchmarkExtraRecordsUpdate(b *testing.B) {
	level := zerolog.GlobalLevel()

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	defer zerolog.SetGlobalLevel(level)

	for _, format := range []string{"json", "hujson", "yaml"} {
		for _, count := range []int{0, 1, 100, 10000} {
			records := make([]tailcfg.DNSRecord, count)
			for i := range records {
				records[i] = tailcfg.DNSRecord{
					Name: fmt.Sprintf(
						"node-%d.example.com",
						i,
					),
					Type:  "A",
					Value: "100.64.0.1",
				}
			}

			var (
				content []byte
				err     error
			)
			if format == "yaml" {
				content, err = yaml.Marshal(records)
			} else {
				content, err = json.Marshal(records)
				if format == "hujson" {
					content = append([]byte("// extra DNS records\n"), content...)
				}
			}

			require.NoError(b, err)
			path := filepath.Join(b.TempDir(), "extra."+format)
			require.NoError(b, os.WriteFile(path, content, 0o600))
			acceptedHash := sha256.Sum256(content)

			for _, changed := range []bool{false, true} {
				for _, implementation := range []struct {
					name   string
					update func(*ExtraRecordsMan)
				}{
					{"original", (*ExtraRecordsMan).updateRecordsOriginal},
					{"candidate", (*ExtraRecordsMan).updateRecords},
				} {
					b.Run(
						fmt.Sprintf(
							"%s/N%d/changed=%t/%s",
							format,
							count,
							changed,
							implementation.name,
						),
						func(b *testing.B) {
							manager := &ExtraRecordsMan{
								path:    path,
								records: set.SetOf(records),
								hash:    acceptedHash,
								updateCh: make(
									chan []tailcfg.DNSRecord,
									1,
								),
								closeCh: make(chan struct{}),
							}

							b.ReportAllocs()
							b.ResetTimer()

							for range b.N {
								if changed {
									b.StopTimer()

									manager.hash = [32]byte{}

									b.StartTimer()
								}

								implementation.update(manager)

								if changed {
									b.StopTimer()
									require.Len(b, manager.updateCh, 1)
									require.Len(b, <-manager.UpdateCh(), count)
									require.Equal(b, acceptedHash, manager.hash)
									b.StartTimer()
								}
							}

							b.StopTimer()
							require.Empty(b, manager.updateCh)
							require.Equal(b, acceptedHash, manager.hash)
							require.Len(b, manager.records, count)
						},
					)
				}
			}
		}
	}
}

// Frozen from d00f135bf:hscontrol/dns/extrarecords.go before the candidate edit;
// only the function name and reader call are renamed.
func (e *ExtraRecordsMan) updateRecordsOriginal() {
	records, newHash, err := readExtraRecordsFromPathOriginal(e.path)
	if err != nil {
		log.Error().Caller().Err(err).Msgf("reading extra records from path: %s", e.path)
		return
	}

	// If there are no records, ignore the update.
	if records == nil {
		return
	}

	e.mu.Lock()

	// If there has not been any change, ignore the update.
	if newHash == e.hash {
		e.mu.Unlock()

		return
	}

	oldCount := e.records.Len()

	e.records = set.SetOf(records)
	e.hash = newHash
	toSend := e.records.Slice()

	log.Trace().Caller().Interface("records", e.records).Msgf("extra records updated from path, count old: %d, new: %d", oldCount, e.records.Len())

	// Release the lock before the (potentially blocking) send so a slow or
	// absent consumer cannot stall Records() readers, and abort the send on
	// shutdown instead of leaking this goroutine on the closed-down channel.
	e.mu.Unlock()

	select {
	case e.updateCh <- toSend:
	case <-e.closeCh:
	}
}

// Frozen from d00f135bf:hscontrol/dns/extrarecords.go; only the name is changed.
func readExtraRecordsFromPathOriginal(path string) ([]tailcfg.DNSRecord, [32]byte, error) {
	var zero [32]byte

	b, err := os.ReadFile(path)
	if err != nil {
		return nil, zero, fmt.Errorf("reading path: %s, err: %w", path, err)
	}

	// If the read was triggered too fast, and the file is not complete, ignore the update
	// if the file is empty. A consecutive update will be triggered when the file is complete.
	if len(b) == 0 {
		return nil, zero, nil
	}

	// Hash first: decoding HuJSON may rewrite comments in b.
	hash := sha256.Sum256(b)

	records, err := util.UnmarshalByExt[[]tailcfg.DNSRecord](path, b)
	if err != nil {
		return nil, zero, fmt.Errorf("unmarshalling records, content: %q: %w", string(b), err)
	}

	return records, hash, nil
}
