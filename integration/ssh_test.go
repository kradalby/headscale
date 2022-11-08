package integration

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
)

func TestSSHOneNamespaceAllToAll(t *testing.T) {
	IntegrationSkip(t)

	retry := func(times int, sleepInverval time.Duration, doWork func() (string, string, error)) (string, string, error) {
		var err error
		for attempts := 0; attempts < times; attempts++ {
			result, stderr, err := doWork()
			if err == nil {
				return result, stderr, nil
			}
			time.Sleep(sleepInverval)
		}

		return "", "", err
	}

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		// Omit versions before 1.24 because they don't support SSH
		"namespace1": len(TailscaleVersions) - 4,
		"namespace2": len(TailscaleVersions) - 4,
	}

	err = scenario.CreateHeadscaleEnv(spec,
		[]tsic.Option{tsic.WithSSH()},
		hsic.WithACLPolicy(
			&headscale.ACLPolicy{
				Groups: map[string][]string{
					"group:integration-test": {"namespace1"},
				},
				ACLs: []headscale.ACL{
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"*:*"},
					},
				},
				SSHs: []headscale.SSH{
					{
						Action:       "accept",
						Sources:      []string{"group:integration-test"},
						Destinations: []string{"group:integration-test"},
						Users:        []string{"ssh-it-user"},
					},
				},
			},
		),
	)
	if err != nil {
		t.Errorf("failed to create headscale environment: %s", err)
	}

	allClients, err := scenario.ListTailscaleClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	err = scenario.WaitForTailscaleSync()
	if err != nil {
		t.Errorf("failed wait for tailscale clients to be in sync: %s", err)
	}

	_, err = scenario.ListTailscaleClientsFQDNs()
	if err != nil {
		t.Errorf("failed to get FQDNs: %s", err)
	}

	success := 0

	for _, client := range allClients {
		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			clientFQDN, _ := client.FQDN()
			peerFQDN, _ := peer.FQDN()

			t.Run(
				fmt.Sprintf("%s-%s", clientFQDN, peerFQDN),
				func(t *testing.T) {
					command := []string{
						"ssh", "-o StrictHostKeyChecking=no", "-o ConnectTimeout=1",
						fmt.Sprintf("%s@%s", "ssh-it-user", peer.Hostname()),
						"'hostname'",
					}

					result, _, err := retry(10, 1*time.Second, func() (string, string, error) {
						return client.Execute(command)
					})
					if err != nil {
						t.Errorf("failed to execute command over SSH: %s", err)
					}

					if strings.Contains(peer.ID(), result) {
						t.Logf(
							"failed to get correct container ID from %s, expected: %s, got: %s",
							peer.Hostname(),
							peer.ID(),
							result,
						)
						t.Fail()
					} else {
						success++
					}
				},
			)
		}
	}

	t.Logf(
		"%d successful pings out of %d",
		success,
		(len(allClients)*len(allClients))-len(allClients),
	)

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}
