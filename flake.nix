{
  description = "headscale - Open Source Tailscale Control server";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    # Reusable Go flake checks (build/test/lint/format); CI runs them via
    # `nix build .#checks.<system>.<name>` instead of bespoke per-tool steps.
    flake-checks.url = "github:kradalby/flake-checks";
    flake-checks.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      flake-checks,
      ...
    }:
    let
      headscaleVersion = self.shortRev or self.dirtyShortRev;
      commitHash = self.rev or self.dirtyRev;
    in
    {
      # NixOS module
      nixosModules = rec {
        # Defaults the package to this flake's: the pre-switch checks need
        # `headscale check`. Priority 1001 sits just below mkDefault, so a
        # user's mkDefault wins instead of conflicting. The overlay, not
        # self.packages, so every system nixpkgs supports evaluates.
        headscale =
          { lib, pkgs, ... }:
          {
            # Dedupes importing it twice, directly and via testkit.
            key = "${toString ./flake.nix}#nixosModules.headscale";
            _file = "${toString ./flake.nix}#nixosModules.headscale";
            imports = [ ./nix/module.nix ];
            services.headscale.package = lib.mkOverride 1001 (self.overlays.default pkgs pkgs).headscale;
          };
        default = headscale;
        # Control node for NixOS VM tests of Tailscale clients, and a peer
        # that joins it; nix/README.md.
        testkit = import ./nix/testkit.nix self;
        testkit-peer = ./nix/testkit-peer.nix;
      };

      overlays.default =
        final: prev:
        let
          pkgs = nixpkgs.legacyPackages.${prev.stdenv.hostPlatform.system};
          # Tracks the newest Go in nixpkgs so a Go release bump is a
          # flake.lock update, not a flake.nix edit.
          buildGo = pkgs.buildGoLatestModule;
          vendorHash = (builtins.fromJSON (builtins.readFile ./flakehashes.json)).vendor.sri;
        in
        {
          headscale = buildGo {
            pname = "headscale";
            version = headscaleVersion;
            src = pkgs.lib.cleanSource self;

            # Only run unit tests when testing a build
            checkFlags = [ "-short" ];

            # vendorHash is read from flakehashes.json; refresh via:
            #   go run ./cmd/vendorhash update
            inherit vendorHash;

            subPackages = [ "cmd/headscale" ];

            meta = {
              mainProgram = "headscale";
            };
          };

          debug-graph = pkgs.callPackage ./hscontrol/assets/debug-graph { };

          headscale-debug = final.headscale.overrideAttrs (old: {
            pname = "headscale-debug";
            tags = (old.tags or [ ]) ++ [ "headscale_debug" ];
            # Share vendoring without pulling the frontend into that derivation.
            goModules = final.headscale.goModules;
            postConfigure = (old.postConfigure or "") + ''
              install -m644 ${final.debug-graph}/elm.js hscontrol/assets/debug-graph/elm.js
            '';
          });

          hi = buildGo {
            pname = "hi";
            version = headscaleVersion;
            src = pkgs.lib.cleanSource self;

            checkFlags = [ "-short" ];
            inherit vendorHash;

            subPackages = [ "cmd/hi" ];
          };

          gotestsum = prev.gotestsum.override {
            buildGoModule = buildGo;
          };

          gotests = prev.gotests.override {
            buildGoModule = buildGo;
          };

          gofumpt = prev.gofumpt.override {
            buildGoModule = buildGo;
          };

          # goimports and friends: they parse Go with the parser of the Go
          # they were built with, so an older one rejects new syntax.
          gotools = prev.gotools.override {
            buildGoModule = buildGo;
            # goimports is wrapped with this go on PATH for module lookups.
            go = pkgs.go_latest;
          };

          golangci-lint-langserver = prev.golangci-lint-langserver.override {
            buildGoModule = buildGo;
          };
        };
    }
    # Explicit: nixpkgs no longer evaluates x86_64-darwin, which
    # eachDefaultSystem still lists.
    // flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ] (
      system:
      let
        pkgs = import nixpkgs {
          overlays = [ self.overlays.default ];
          inherit system;
        };
        buildDeps = with pkgs; [
          git
          go_latest
          gnumake
        ];
        elmDeps = with pkgs; [
          elmPackages.elm
          elmPackages.elm-format
          elm2nix
          nixfmt
        ];
        debug-graph = pkgs.debug-graph;
        devDeps =
          with pkgs;
          buildDeps
          ++ elmDeps
          ++ [
            golangci-lint
            golangci-lint-langserver
            prettier
            nixfmt
            goreleaser
            nfpm
            gotestsum
            gotests
            gofumpt
            gopls
            gotools

            gh
            gh-actions-lock
            ksh
            ko
            yq-go
            ripgrep
            postgresql

            # External clients exercised by the Tailscale-compatible v2 API
            # roundtrip tests (TestAPIv2). Binaries: tofu, tscli.
            opentofu
            tscli
            python3Packages.mdformat
            python3Packages.mdformat-footnote
            python3Packages.mdformat-frontmatter
            python3Packages.mdformat-mkdocs
            prek

            # 'dot' is needed for pprof graphs
            # go tool pprof -http=: <source>
            graphviz
          ]
          ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [ traceroute ];

        # Add entry to build a docker image with headscale
        # caveat: only works on Linux
        #
        # Usage:
        # nix build .#headscale-docker
        # docker load < result
        headscale-docker = pkgs.dockerTools.buildLayeredImage {
          name = "headscale";
          tag = headscaleVersion;
          # CA certificates for outbound HTTPS, such as the DERP map.
          contents = [
            pkgs.headscale
            pkgs.cacert
          ];
          config.Entrypoint = [ (pkgs.headscale + "/bin/headscale") ];
          config.Env = [ "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt" ];
        };

        # Go flake checks from the flake-checks library. CI gates on
        # `nix build .#checks.<system>.<name>`; the logic lives here, not in
        # bespoke workflow steps. Linux-only: parts of the tree are
        # Linux-specific and the pure unit subset is validated by CI.
        fc = flake-checks.lib;
        common = {
          inherit pkgs;
          root = ./.;
          pname = "headscale";
          version = headscaleVersion;
          vendorHash = (builtins.fromJSON (builtins.readFile ./flakehashes.json)).vendor.sri;
          goPkg = pkgs.go_latest;
          # //go:embed targets and test-read files outside the default whitelist.
          embedDirs = [
            ./hscontrol/assets
            ./hscontrol/db/schema.sql
          ];
          extraSrc = [
            ./hscontrol/testdata
            ./hscontrol/config/testdata
            ./hscontrol/db/testdata
            ./hscontrol/policy/v2/testdata
          ];
          treefmtExtra.settings.global.excludes = [
            "hscontrol/assets/debug-graph/elm.js"
            "hscontrol/assets/debug-graph/elm-stuff/**"
            "hscontrol/assets/debug-graph/.elm/**"
          ];
        };
        goChecks = {
          build = fc.goBuild (common // { subPackages = [ "cmd/headscale" ]; });

          # Tagged builds embed elm.js, which only Nix produces (never
          # committed): these checks build it first, and outside Nix
          # `make debug-graph` installs it for go build and go test.
          debug-build = pkgs.headscale-debug;

          debug-gotest = fc.goTest (
            common
            // {
              name = "headscale-debug-gotest";
              goTags = [ "headscale_debug" ];
              goRace = true;
              testPackages = "./hscontrol ./hscontrol/state ./hscontrol/graph";
              testFlags = [
                "-run='Test(DebugGraph|Inspect)'"
                "-p=2"
              ];
              testEnv = ''
                export CGO_ENABLED=1
                install -m644 ${debug-graph}/elm.js hscontrol/assets/debug-graph/elm.js
              '';
            }
          );

          # The pure unit subset. The root ./integration package (Docker) and
          # ./hscontrol/servertest (slow: 10s+ convergence plus race/stress/HA
          # property tests — run by the servertest workflow instead) are dropped
          # from the test set but kept in source so cmd/hi and friends still
          # compile. Pure integration helper tests remain included.
          # TestPostgres* needs a server (the SQLite equivalents still
          # run). This check keeps CGO off; gorace below enables it for tests.
          gotest = fc.goTest (
            common
            // {
              testExclude = [
                "/integration$"
                "/hscontrol/servertest"
              ];
              goSkip = [ "TestPostgres" ];
              testEnv = "export CGO_ENABLED=0";
            }
          );

          # -race needs cgo; release build and dev shell stay CGO-free.
          # Test hscontrol recursively; servertest runs in its own workflow, without -race.
          gorace = fc.goTest (
            common
            // {
              name = "headscale-gorace";
              goRace = true;
              testEnv = "export CGO_ENABLED=1";
              # -race slows the policy suites past go test's default 10m
              # per-package timeout on a loaded builder.
              testFlags = [
                "-p=2"
                "-timeout=30m"
              ];
              goSkip = [ "TestPostgres" ];
              testPackages = "./hscontrol/...";
              testExclude = [ "/hscontrol/servertest" ];
            }
          );

          # Full-tree golangci-lint (gofumpt, gci, etc.); uses the overlay's
          # golangci-lint built against the pinned Go. The headscale_debug
          # pass needs only a file for go:embed, not the Elm build.
          golangci-lint = (fc.goLint common).overrideAttrs (old: {
            buildPhase = old.buildPhase + ''
              : > hscontrol/assets/debug-graph/elm.js
              golangci-lint run --build-tags=headscale_debug ./...
            '';
          });

          # nixfmt + prettier, excluding generated output. goFmt = "off":
          # Go formatting (gofumpt, gci) is enforced by the golangci-lint
          # check, not treefmt. prettierExts matches the old prettier-lint glob
          # (no json: testdata fixtures are hand-formatted).
          formatting = fc.goFormat (
            common
            // {
              goFmt = "off";
              prettier = true;
              prettierExts = [
                "ts"
                "js"
                "md"
                "yaml"
                "yml"
                "sass"
                "css"
                "scss"
                "html"
              ];
              # Mirror .prettierignore (docs/ are mkdocs-flavoured; gen/ generated).
              fmtExclude = [
                ./gen
                ./docs
              ];
            }
          );
        };

        # nix/options.generated.nix: what the binary prints, every default
        # and example of its option's type, the examples loaded unchanged by
        # headscale, and descriptions that render.
        nixos-options =
          let
            inherit (pkgs) lib;
            options = import ./nix/options.generated.nix { inherit lib; };
            each = f: lib.mapAttrsRecursiveCond (o: !lib.isOption o) (_: f) options;
            eval = config: lib.evalModules { modules = [ { inherit options config; } ]; };
            defaults = eval (each (o: lib.mkIf (!(o ? default)) o.example));
            examples = eval (each (o: o.example));
            doc = pkgs.nixosOptionsDoc { inherit (examples) options; };
            # Development tool, not shipped: loads a file as headscale does.
            files = pkgs.headscale.overrideAttrs { subPackages = [ "tools/configgen/files" ]; };
            # Values of the wrong shape: each must fail the option it is set on.
            rejected = {
              listen_addr = [
                "8080"
                "::1:8080"
                "0.0.0.0:abc"
              ];
              "node.expiry" = [
                "30"
                ""
                "3 hours"
              ];
              unix_socket_permission = [
                "0778"
                "07777"
                504
              ];
              "prefixes.v4" = [
                "100.64.0.1"
                "100.64.0.0/33"
              ];
              "prefixes.v6" = [ "fd7a::/129" ];
              "oidc.issuer" = [
                "headscale.example.com"
                "ftp://x"
                "https://"
              ];
              "oidc.client_secret" = [ "hunter2" ];
              "database.postgres.pass" = [ "hunter2" ];
              # Relative to the config, which is in the store.
              "policy.path" = [
                "policy.hujson"
                42
              ];
              "tls.cert_path" = [ "cert.pem" ];
              "derp.paths" = [ [ "derp.yaml" ] ];
              # A key in the store is world-readable.
              "noise.private_key_path" = [
                ./flake.nix
                "${./flake.nix}"
                "noise_private.key"
              ];
              "tls.key_path" = [ "${./flake.nix}" ];
              "database.sqlite.path" = [ "db.sqlite" ];
              "dns.extra_records" = map (r: [ ({ name = "grafana.example.com"; } // r) ]) [
                { value = "grafana"; }
                { value = "256.1.1.1"; }
                {
                  type = "CNAME";
                  value = "100.64.0.3";
                }
                { }
              ];
            };
            # Only the option itself is forced, so nothing else can fail it.
            fails =
              name: value:
              let
                path = lib.splitString "." name;
                config = (eval (lib.setAttrByPath path value)).config;
              in
              lib.hasAttrByPath path options
              && !(builtins.tryEval (builtins.deepSeq (lib.getAttrFromPath path config) null)).success;
            accepted = lib.concatLists (
              lib.mapAttrsToList (
                name: values: map (v: "${name} = ${builtins.toJSON v}") (lib.filter (v: !fails name v) values)
              ) rejected
            );
          in
          assert lib.assertMsg (
            accepted == [ ]
          ) "nixos-options: types accept ${lib.concatStringsSep "; " accepted}";
          pkgs.runCommand "headscale-nixos-options"
            {
              nativeBuildInputs = [
                pkgs.headscale
                pkgs.yq-go
                pkgs.jq
              ];
              # Unused; evaluating it checks every default against its type.
              defaults = builtins.toJSON defaults.config;
              examples = builtins.toJSON examples.config;
              passAsFile = [ "examples" ];
            }
            ''
              headscale generate nixos-options | diff -u ${./nix/options.generated.nix} -
              cp "$examplesPath" examples.json
              ${files}/bin/files -load examples.json > loaded.yaml
              jq -S . examples.json > want.json
              yq -o json . loaded.yaml | jq -S . > got.json
              diff -u want.json got.json
              # A secret's NixOS form renders as Nix source takes it.
              grep -F '"file:\''${CREDENTIALS_DIRECTORY}/oidc_client_secret"' ${doc.optionsCommonMark}
              touch $out
            '';
      in
      {
        devShells.debug-graph = pkgs.mkShell {
          packages = elmDeps ++ [ pkgs.gnumake ];
        };

        # `nix develop`
        devShells.default = pkgs.mkShell {
          buildInputs = devDeps ++ [
            (pkgs.writeShellScriptBin "nix-vendor-sri" ''
              set -eu
              exec go run ./cmd/vendorhash update "$@"
            '')

            (pkgs.writeShellScriptBin "go-mod-update-all" ''
              cat go.mod | ${pkgs.ripgrep}/bin/rg "\t" | ${pkgs.ripgrep}/bin/rg -v '^\s*//' | ${pkgs.ripgrep}/bin/rg -v indirect | ${pkgs.gawk}/bin/awk '{print $1}' | ${pkgs.findutils}/bin/xargs go get -u
              go mod tidy
            '')
          ];

          shellHook = ''
            export PATH="$PWD/result/bin:$PATH"
            export CGO_ENABLED=0
          '';
        };

        # `nix build`
        packages = with pkgs; {
          inherit headscale headscale-debug;
          inherit headscale-docker;
          inherit debug-graph;
          default = headscale;
        };

        # `nix run`
        apps.headscale = flake-utils.lib.mkApp {
          drv = pkgs.headscale;
        };
        apps.default = flake-utils.lib.mkApp {
          drv = pkgs.headscale;
        };

        # `nix fmt` is built from the same treefmt module as the formatting
        # check, so the two cannot disagree. Every formatter the tree is judged
        # by lives here, not in a hand-kept list of pre-commit hooks.
        formatter = fc.formatter (
          common
          // {
            goFmt = "off";
            prettier = true;
          }
        );

        # Gated to Linux: parts of the tree are Linux-specific, and the VM
        # tests need KVM.
        checks = {
          debug-graph =
            pkgs.runCommand "headscale-debug-graph-check"
              {
                nativeBuildInputs = [
                  pkgs.elmPackages.elm-format
                  pkgs.nodejs
                ];
              }
              ''
                cp ${./hscontrol/assets/debug-graph/app.js} app.js
                cp ${./hscontrol/assets/debug-graph/index.html} index.html
                cp ${./hscontrol/assets/debug-graph/bridge-check.js} bridge-check.js
                node bridge-check.js
                elm-format --validate ${./hscontrol/assets/debug-graph/src}
                test -s ${debug-graph}/elm.js
                touch "$out"
              '';
        }
        // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux (
          goChecks
          // {
            headscale = pkgs.testers.runNixOSTest (import ./nix/tests/headscale.nix self);
            headscale-checks = pkgs.testers.runNixOSTest (import ./nix/tests/checks.nix self);
            nixos-module = import ./nix/tests/module.nix self pkgs;
            inherit nixos-options;
          }
        );
      }
    );
}
