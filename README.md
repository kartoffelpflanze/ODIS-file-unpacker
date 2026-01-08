# ODIS file unpacker

Nefarious Motorsports forum thread: [http://nefariousmotorsports.com/forum/index.php?topic=24032](http://nefariousmotorsports.com/forum/index.php?topic=24032)

---

This Python project is meant to unpack the JAR archives containing encrypted Java .class files from the `plugins` folder, and also all the data from `DIDB/data`.

Extracting data from `DIDB/db` can be done using my other project: [ODIS-project-explorer -  dumpHSQLDB](https://github.com/kartoffelpflanze/ODIS-project-explorer/blob/main/dumpHSQLDB.py).

## A bit of info

> [!NOTE]
> No databases will ever be provided!
> Please bring your own :)

The following libraries must be installed beforehand:
```powershell
python -m pip install pycryptodome
python -m pip install blowfish
```

The DIDB data files (located usually in `C:\ProgramData\OS\DIDB\data`) seem to only be used for the Guided Fault Finding feature.
They contain PNG images, HTML documents, Java classes, pretty much everything you would see during GFF and behind the scenes for automation.

The plugins (located next to the executable, so in `C:\Program Files\OS\plugins`) are all the Java libraries that ODIS uses.
Only some of the JAR archives in this folder contain encrypted classes (i.e. only those specific to ODIS).

## Script info

### `unpack_plugins`

This script will go through the given folder and will unpack all JAR archives that are protected.
Unprotected archives are skipped.

> [!TIP]
> ```powershell
> python unpack_plugins.py "C:\Program Files\OS\plugins" "O:/Plugins"
> ```

### `unpack_didb_data`

This script searches for JAR or ZIP archives (recursively) starting from the given folder.
It unpacks all files, maintaining the original structure.

It must be mentioned that these archives are massive, so maybe copy the files you want to some other folder instead of asking the script to unpack everything.

> [!TIP]
> ```powershell
> python unpack_didb_data.py "C:\ProgramData\OS\DIDB\data" "O:/DIDB_data"
> ```

## Boring details - how I did this

The plan was to attach a Java agent to the JVM created by ODIS, and dump classes when they are loaded, since they would already have been decrypted at that point.
Of course they added `-XX:+DisableAttachMechanism` to stop that. It must first be removed before I can attach.

ODIS has anti-debugging protection. However this is easily bypassed with the plugin ScyllaHide set to the VMProtect profile.

Setting a breakpoint on JNI_CreateJavaVM shows a pointer to the string `-XX:+DisableAttachMechanism` in register RAX.
I have no clue why, but just editing the string in memory, in any way, causes JVM creation to return non-zero.

It seems like register R8 contains a pointer to some configuration structure. At offset 0x50 from that address, there are clearly some pointers, 16 bytes apart.
The 5th pointer goes to the string we want to remove from the arguments list. So I just changed the pointer to the previous one in the list.
I guess this means I'm giving it some argument (`--add-modules=...`) twice, but it doesn't complain. Now JVM creation return zero (good) and I can attach my agent.

Letting it run for a bit, my script dumped a lot of decrypted class files. But I'm interested in decrypting them myself.
One of the classes is `b.ClassLoader`. Opening it up in jd-gui reveals the code responsible for decrypting .class files.
The algorithm used is AES, with the key defined at the top of that file.

After decrypting all protected plugins, I archived them and opened them in jd-gui, to save the decompiled source code all at once.
What followed were a bit too many hours of searching the source code for how DIDB data is handled.

In the end, I found those files use the Blowfish algorithm (ECB mode), with the key defined at the top of `de.volkswagen.odis.vaudas.gfs.zecret.security.KeySource`.
Additionally, some files are also compressed with GZIP, so they must be decompressed after decryption.

---

Some AI might have been harmed in the making of this slop.
