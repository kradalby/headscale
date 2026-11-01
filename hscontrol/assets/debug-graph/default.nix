{
  lib,
  stdenvNoCC,
  elmPackages,
  nodejs,
}:

stdenvNoCC.mkDerivation {
  pname = "headscale-debug-graph";
  version = "1";

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./elm.json
      ./src
    ];
  };

  nativeBuildInputs = [ elmPackages.elm ];
  nativeCheckInputs = [ nodejs ];
  dontConfigure = true;

  preBuild = elmPackages.fetchElmDeps {
    elmPackages = import ./elm-srcs.nix;
    elmVersion = elmPackages.elm.version;
    registryDat = ./registry.dat;
  };

  buildPhase = ''
    runHook preBuild
    elm make src/Main.elm --optimize --output=elm.js
    runHook postBuild
  '';

  doCheck = true;
  checkPhase = ''
    runHook preCheck
    elm make src/FrontendCheck.elm --optimize --output=frontend-check.js
    node -e 'require("./frontend-check.js").Elm.FrontendCheck.init().ports.results.subscribe(checks => {
      console.log(checks);
      process.exit(checks.length > 0 && checks.every(check => check.passed) ? 0 : 1);
    });'
    runHook postCheck
  '';

  # The compiled packages' licenses require their notices to travel with it.
  installPhase = ''
    runHook preInstall
    mkdir -p "$out"
    {
      echo '/*! The Elm packages compiled into this file, with their licenses.'
      for license in "$ELM_HOME"/*/packages/*/*/*/LICENSE; do
        if grep -qF '*/' "$license"; then
          echo "$license would end the license comment" >&2
          exit 1
        fi
        package=''${license#"$ELM_HOME"/*/packages/}
        printf '\n%s\n\n' "''${package%/LICENSE}"
        cat "$license"
      done
      echo '*/'
      cat elm.js
    } > "$out/elm.js"
    chmod 444 "$out/elm.js"
    runHook postInstall
  '';
}
