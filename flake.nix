# aws-greengrass-system-log-forwarder - AWS Greengrass component for forwarding
# logs to CloudWatch.
#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

{
  description = "Chnage here: description here";
  inputs.flakelight.url = "github:nix-community/flakelight";
  outputs = { flakelight, ... }@inputs: flakelight ./.
    ({ lib, config, ... }:
      let
        inherit (builtins) fromJSON;
        inherit (lib) mapAttrs readFile mapAttrsToList toUpper;

        filteredSrc = lib.fileset.toSource {
          root = ./.;
          fileset = lib.fileset.unions [
            ./CMakeLists.txt
            ./src
            ./fc_deps.json
            ./.clang-tidy
            ./dep_modules
          ];
        };

        llvmStdenv = pkgs: pkgs.overrideCC pkgs.llvmPackages.stdenv
          (pkgs.llvmPackages.stdenv.cc.override
            { inherit (pkgs.llvmPackages) bintools; });

        deps = pkgs: mapAttrs (_: v: pkgs.fetchgit (v // { fetchSubmodules = true; }))
          (fromJSON (readFile ./fc_deps.json));

        fetchContentFlags = pkgs: mapAttrsToList
          (n: v: "-DFETCHCONTENT_SOURCE_DIR_${toUpper n}=${v}")
          (deps pkgs);

      in
      {
        systems = lib.systems.flakeExposed;
        inherit inputs;

        devShell = pkgs: {
          packages = with pkgs; [ clang-tools clangd-tidy git ];
          env.NIX_HARDENING_ENABLE = "";
          shellHook = ''
            export MAKEFLAGS=-j
          '';
        };

        devShells.clang = { lib, pkgs, ... }: {
          imports = [ (config.devShell pkgs) ];
          stdenv = lib.mkForce (llvmStdenv pkgs);
        };

        formatters = { llvmPackages, cmake-format, nodePackages, ... }:
          let
            fmt-c = "${llvmPackages.clang-unwrapped}/bin/clang-format -i";
            fmt-cmake = "${cmake-format}/bin/cmake-format -i";
            fmt-yaml =
              "${nodePackages.prettier}/bin/prettier --write --parser yaml";
          in
          {
            "*.c" = fmt-c;
            "*.h" = fmt-c;
            "CMakeLists.txt" = fmt-cmake;
            ".clang*" = fmt-yaml;
          };

        pname = "gg-sys-log-forwarder";
        package = { pkgs, stdenv, pkg-config, cmake, ninja, defaultMeta }:
          stdenv.mkDerivation {
            name = "gg-sys-log-forwarder";
            src = filteredSrc;
            nativeBuildInputs = [ pkg-config cmake ninja ];
            buildInputs = [ ];
            cmakeBuildType = "MinSizeRel";
            cmakeFlags = (fetchContentFlags pkgs) ++ [ "-DENABLE_WERROR=1" ];
            dontStrip = true;
            meta = defaultMeta;
          };

        checks =
          let
            clangBuildDir = { pkgs, pkg-config, clang-tools, cmake, ... }:
              (llvmStdenv pkgs).mkDerivation {
                name = "clang-cmake-build-dir";
                nativeBuildInputs = [ pkg-config clang-tools ];
                buildInputs = [ ];
                buildPhase = ''
                  ${cmake}/bin/cmake -B $out -S ${filteredSrc} \
                    -D CMAKE_BUILD_TYPE=Debug ${toString (fetchContentFlags pkgs)}\
                    rm $out/CMakeFiles/CMakeConfigureLog.yaml
                '';
                dontUnpack = true;
                dontPatch = true;
                dontConfigure = true;
                dontInstall = true;
                dontFixup = true;
                allowSubstitutes = false;
              };
          in
          {
            build-clang = pkgs: pkgs.gg-sys-log-forwarder.override
              { stdenv = llvmStdenv pkgs; };

            build-musl-pi = pkgs: pkgs.pkgsCross.muslpi.gg-sys-log-forwarder;

            clang-tidy = pkgs: ''
              set -eo pipefail
              PATH=${lib.makeBinPath
                (with pkgs; [clangd-tidy clang-tools fd])}:$PATH
              clangd-tidy -j$(nproc) -p ${clangBuildDir pkgs} --color=always \
                $(fd . ${filteredSrc}/src -e c -e h) |\
                sed 's|\.\.${filteredSrc}/||'
            '';

            iwyu = pkgs: ''
              set -eo pipefail
              PATH=${lib.makeBinPath
                (with pkgs; [include-what-you-use fd])}:$PATH
              white=$(printf "\e[1;37m")
              red=$(printf "\e[1;31m")
              clear=$(printf "\e[0m")
              iwyu_tool.py -o clang -j $(nproc) -p ${clangBuildDir pkgs} \
                $(fd . ${filteredSrc}/ -e c) -- \
                -Xiwyu --error -Xiwyu --check_also="${filteredSrc}/*" \
                -Xiwyu --mapping_file=${./.}/misc/iwyu_mappings.yml |\
                { grep error: || true; } |\
                sed 's|\(.*\)error:\(.*\)|'$white'\1'$red'error:'$white'\2'$clear'|' |\
                sed 's|${filteredSrc}/||'
            '';

            cmake-lint = pkgs: ''
              ${pkgs.cmake-format}/bin/cmake-lint \
                $(${pkgs.fd}/bin/fd '.*\.cmake|CMakeLists.txt') \
                --suppress-decorations
            '';

            spelling = pkgs: ''
              ${pkgs.nodePackages.cspell}/bin/cspell "**" --quiet
              ${pkgs.coreutils}/bin/sort -cuf misc/dictionary.txt
            '';
          };

        withOverlays = final: prev: {
          clangd-tidy = final.callPackage
            ({ python3Packages }:
              python3Packages.buildPythonPackage rec {
                pname = "clangd_tidy";
                version = "1.1.0.post1";
                format = "pyproject";
                src = final.fetchPypi {
                  inherit pname version;
                  hash = "sha256-wqwrdD+8kd2N0Ra82qHkA0T2LjlDdj4LbUuMkTfpBww=";
                };
                buildInputs = with python3Packages; [ setuptools-scm ];
                propagatedBuildInputs = with python3Packages; [
                  attrs
                  cattrs
                  typing-extensions
                ];
              })
            { };
        };
      });
}
