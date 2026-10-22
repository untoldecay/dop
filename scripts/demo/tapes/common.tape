# Shared header for every demo tape. record.sh copies the tapes to the
# demo root and replaces __ROOT__ and __THEME__ before running VHS.
# 4:3 at 1280 wide, big type: the clips are read on a phone feed.
Set Shell bash
Set FontSize 28
Set Width 1280
Set Height 960
Set Padding 40
Set Theme __THEME__
Set TypingSpeed 40ms
Set Framerate 30
Env HOME "__ROOT__/home"
Env PATH "__ROOT__/bin:/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"
Env DOP_THEME "light"
Env DOP_NO_NOTIFY "1"
Env DOP_NO_KEYCHAIN "1"
Env DOP_ALLOW_FILE_KEYS "1"
Env DOP_NO_AUTO_PULL "1"
Env PS1 "\[\e[90m\]camille@mini\[\e[0m\] ~ % "
Env PS2 "\[\e[90m\]>\[\e[0m\] "
