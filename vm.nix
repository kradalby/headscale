{
  nixpkgs,
  microvm,
  mkDevDeps,
  self,
  overrides ? {},
}: let
  baseVmConfig = nixpkgs.lib.nixosSystem {
    system = "x86_64-linux";
    modules = [
      microvm.nixosModules.microvm
      ({
        lib,
        pkgs,
        ...
      }:
        lib.mkMerge [
          {
            # Configure dev user
            users.users.dev = {
              isNormalUser = true;
              password = "dev";
              extraGroups = ["wheel" "docker"];
              shell = pkgs.fish;
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
              mem = 16384; # 16GB RAM
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
          }
          overrides
        ])
    ];
    specialArgs = {inherit microvm;};
  };

  # VM configuration builder function
  mkVmConfig = name: vmOverrides: nixpkgs.lib.nixosSystem {
    system = "x86_64-linux";
    modules = [
      microvm.nixosModules.microvm
      ({
        lib,
        pkgs,
        ...
      }:
        lib.mkMerge [
          {
            # Configure dev user
            users.users.dev = {
              isNormalUser = true;
              password = "dev";
              extraGroups = ["wheel" "docker"];
              shell = pkgs.fish;
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
              mem = 16384; # 16GB RAM
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
          }
          vmOverrides
        ])
    ];
    specialArgs = {inherit microvm;};
  };
in {
  # Base VM configuration (for backwards compatibility)
  vm = baseVmConfig;

  # VM configuration builder function
  mkVm = mkVmConfig;


  # Generate 5 devvm configurations (devvm01-devvm05) with 80GB storage
  devvms = nixpkgs.lib.listToAttrs (map (i: let
    devvmNum = 
      if i < 10
      then "0${toString i}"
      else toString i;
    devvmName = "devvm${devvmNum}";
  in {
    name = devvmName;
    value = mkVmConfig devvmName {
      microvm.interfaces = nixpkgs.lib.mkForce [
        {
          type = "tap";
          id = "tap-${devvmName}";
          mac = "02:00:00:01:${devvmNum}:01";
        }
      ];
      microvm.volumes = nixpkgs.lib.mkForce [
        {
          image = "${devvmName}-root.img";
          mountPoint = "/";
          size = 81920; # 80GB
          fsType = "ext4";
          autoCreate = true;
        }
        {
          image = "${devvmName}-nix-store.img";
          mountPoint = "/nix/.rw-store";
          size = 16384; # 16GB nix store overlay
          autoCreate = true;
        }
      ];
      networking.hostName = nixpkgs.lib.mkForce "headscale-${devvmName}";
    };
  }) (nixpkgs.lib.range 1 5));

  # Generate runner configurations (runner01-runner20)
  runners = nixpkgs.lib.listToAttrs (map (i: let
    runnerNum =
      if i < 10
      then "0${toString i}"
      else toString i;
    runnerName = "runner${runnerNum}";
  in {
    name = runnerName;
    value = mkVmConfig runnerName {
      microvm.interfaces = nixpkgs.lib.mkForce [
        {
          type = "tap";
          id = "tap-${runnerName}";
          mac = "02:00:00:00:${runnerNum}:01";
        }
      ];
      microvm.volumes = nixpkgs.lib.mkForce [
        {
          image = "${runnerName}-root.img";
          mountPoint = "/";
          size = 16384; # 16GB root disk
          fsType = "ext4";
          autoCreate = true;
        }
        {
          image = "${runnerName}-nix-store.img";
          mountPoint = "/nix/.rw-store";
          size = 16384; # 16GB nix store overlay
          autoCreate = true;
        }
      ];
      networking.hostName = nixpkgs.lib.mkForce "headscale-${runnerName}";
    };
  }) (nixpkgs.lib.range 1 20));
}
