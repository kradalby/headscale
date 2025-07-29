{
  nixpkgs,
  microvm,
  mkDevDeps,
  self,
  overrides ? {},
}: let
  # Common VM configuration shared by all VMs
  commonVmConfig = {
    lib,
    pkgs,
    ...
  }: {
    # Configure dev user
    users.users.dev = {
      isNormalUser = true;
      password = "dev";
      extraGroups = ["wheel" "docker"];
      shell = pkgs.fish;
      openssh.authorizedKeys.keys = [
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBV4ZjlUvRDs70qHD/Ldi6OTkFpDEFgfbXbqSnaL2Qup"
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOm0+vlPKTRMQm9teF/bCrTPEDEqs1m+B5kMZtuLKh2rDLYM2uwsLPjNjaIlFQfkUn2vyAqGovyKOVR7Q/Z28yo="
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGqesfGzltPA+pNVQ667T1tKzQoz09qTcoQshygxl73I3EbYD5vnHFtC+tnziVbfxSx8ZDRvPDN7vHEalE5U3JU="
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJjAKM+WX/sNJwMcgOv87DXfeXD/fGG7RyCF8svQNbLL"
      ];
    };

    # Configure root user
    users.users.root.password = "root";

    # Enable sudo for dev user
    security.sudo = {
      enable = true;
      wheelNeedsPassword = false;
    };

    # SSH configuration
    services.openssh = {
      enable = true;
      settings = {
        PermitRootLogin = "yes";
        PasswordAuthentication = true;
      };
    };

    # MicroVM configuration
    microvm = {
      hypervisor = "qemu";
      socket = "control.socket";
      mem = 12288; # 12GB RAM
      vcpu = 4; # 4 CPU cores
      interfaces = [
        {
          type = "tap";
          id = "tap-vm";
          mac = "02:00:00:00:00:02";
        }
      ];
      shares = [
        {
          proto = "9p";
          tag = "ro-store";
          source = "/nix/store";
          mountPoint = "/nix/.ro-store";
        }
      ];
      # Enable writable overlay on top of read-only store
      writableStoreOverlay = "/nix/.rw-store";

      # Persistent volumes
      volumes = [
        {
          image = "vm-root.img";
          mountPoint = "/";
          size = 16384; # 16GB root disk
          fsType = "ext4";
          autoCreate = true;
        }
        {
          image = "vm-nix-store.img";
          mountPoint = "/nix/.rw-store";
          size = 16384; # 16GB nix store overlay
          autoCreate = true;
        }
      ];
    };

    # Network configuration
    systemd.network.enable = true;
    networking.hostName = "headscale-dev-vm";
    networking.firewall.enable = false;

    # Docker configuration
    virtualisation.docker = {
      enable = true;
      enableOnBoot = true;
      daemon.settings = {
        data-root = "/var/lib/docker";
        storage-driver = "overlay2";
        exec-opts = ["native.cgroupdriver=systemd"];
        log-driver = "json-file";
        log-opts = {
          max-size = "10m";
          max-file = "3";
        };
      };
    };

    # Enable necessary kernel modules for Docker
    boot.kernelModules = ["overlay" "br_netfilter"];
    boot.kernel.sysctl = {
      "net.bridge.bridge-nf-call-iptables" = 1;
      "net.bridge.bridge-nf-call-ip6tables" = 1;
      "net.ipv4.ip_forward" = 1;
    };

    # Install all Headscale dev dependencies
    environment.systemPackages =
      (mkDevDeps (import nixpkgs {
        overlays = [self.overlay];
        system = "x86_64-linux";
      }))
      ++ (with pkgs; [
        # Additional utilities for VM
        vim
        curl
        wget
        htop
        tmux
        fish
        docker
        docker-compose
        nodejs_24
        uv
        python3
      ]);

    # Enable fish
    programs.fish.enable = true;

    # Configure Nix with flakes support
    nix = {
      settings = {
        trusted-users = ["root" "dev"];
        experimental-features = ["nix-command" "flakes"];
      };
    };

    # Set system version
    system.stateVersion = "25.05";
  };

  # VM configuration builder function
  mkVmConfig = name: vmOverrides:
    nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        microvm.nixosModules.microvm
        ({
          lib,
          pkgs,
          ...
        }:
          lib.mkMerge [
            (commonVmConfig {inherit lib pkgs;})
            vmOverrides
          ])
      ];
      specialArgs = {inherit microvm;};
    };

  # Helper function to generate VM configurations
  mkVmSet = {
    prefix,
    count,
    rootSize ? 16384,
    macPrefix ? "00",
    storeSize ? 16384,
    overrides ? {},
  }:
    nixpkgs.lib.listToAttrs (map (i: let
      num = nixpkgs.lib.strings.fixedWidthNumber 2 i;
      name = "${prefix}${num}";
    in {
      inherit name;
      value = mkVmConfig name (nixpkgs.lib.mkMerge [
        {
          microvm.interfaces = nixpkgs.lib.mkForce [
            {
              type = "tap";
              id = "tap-${name}";
              mac = "02:00:00:${macPrefix}:${num}:01";
            }
          ];
          microvm.volumes = nixpkgs.lib.mkForce [
            {
              image = "${name}-root.img";
              mountPoint = "/";
              size = rootSize;
              fsType = "ext4";
              autoCreate = true;
            }
            {
              image = "${name}-nix-store.img";
              mountPoint = "/nix/.rw-store";
              size = storeSize;
              autoCreate = true;
            }
          ];
          networking.hostName = nixpkgs.lib.mkForce "headscale-${name}";
        }
        overrides
      ]);
    }) (nixpkgs.lib.range 1 count));
in {
  # Base VM configuration (for backwards compatibility)
  vm = mkVmConfig "vm" overrides;

  # VM configuration builder function
  mkVm = mkVmConfig;

  # Generate 5 devvm configurations (devvm01-devvm05) with 80GB storage
  devvms = mkVmSet {
    prefix = "devvm";
    count = 5;
    rootSize = 81920; # 80GB
    macPrefix = "01";
  };

  # Generate runner configurations (runner01-runner20)
  runners = mkVmSet {
    prefix = "runner";
    count = 20;
    macPrefix = "00";
  };
}
