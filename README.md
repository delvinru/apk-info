# apk-info

APK parser on rust with python support.

## FAQ

- Why not just use androguard?

Almost all of my projects are born from something that is inconvenient to use.
Androguard is a great tool in itself, but it is simply not possible to maintain it (in my opinion). It is also not suitable for analyzing a large number of files due to the fact that all the logic is written in not very optimized python.

- I want to modify the apk, how do I do it using this library?

The library is designed for read-only mode only, because i need a good tool with which i can easily and quickly extract information from the apk.

## Credits

- [androguard](https://github.com/androguard/androguard)
- [apkInspector](https://github.com/erev0s/apkInspector)
