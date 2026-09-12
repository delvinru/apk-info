Output docs/assets/demo.gif

Set Shell "bash"

Set FontSize 28
Set Width 1800
Set Height 1600
Set Padding 24
Set Margin 0
Set Theme "Dracula"
Set TypingSpeed 50ms

# hidden setup: minimal docs-style "> " prompt, not shown in the GIF
Hide
Type "export PS1='\e[38;5;212m> \e[0m'"
Enter
Type "clear"
Enter
Show

Type "apk-info show malware.apk"
Enter
Sleep 3s

Hide
Type "clear"
Enter
Show

Type "apk-info show --sigs malware.apk"
Enter
Sleep 6s
