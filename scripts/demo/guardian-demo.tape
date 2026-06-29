# VHS tape for the README hero demo. Regenerate with:
#   cargo build --release -p guardian-cli -p guardian-daemon
#   vhs scripts/demo/guardian-demo.tape           # run from the repo root
# Produces scripts/demo/assets/guardian-demo.gif.
Output scripts/demo/assets/guardian-demo.gif

Set Shell "bash"
Set FontSize 20
Set Width 1200
Set Height 820
Set Padding 26
Set Framerate 24
Set TypingSpeed 45ms
Set PlaybackSpeed 1.0

Type "GUARDIAN_BIN=target/release/guardian ./scripts/demo/play.sh"
Sleep 700ms
Enter
Sleep 23s
