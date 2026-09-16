set -e

# CustomDopamine: single-target build (iOS 15.x bucket only) using the
# SSH-enabled bootstrap variant, matching what DOBootstrapper.m's live
# code path (bootstrapVersion hardcoded to "1800") actually expects.
curl -L https://apt.procurs.us/bootstraps/1800/bootstrap-ssh-iphoneos-arm64.tar.zst --output bootstrap_1800.tar.zst
