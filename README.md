# ELFShield

ELF 加固，暂时只支持dalvik模式，后续完善

# 使用方式

> 1.  clone 项目至本地
> 2.  在 ELFShield 文件夹执行 ndk-build ，可以修改 jni\Application.mk 生成你所需平台的 so 文件，so名为 libelf_loader.so
> 3.  把生成的 libelf_loader.so 拷贝至 merge 文件夹 , 再把需要加固的拷贝至 merge 文件夹，一定要在保证平台的一致，**目前需要加固的文件需固定命名为 libnative-lib.so ，然后把 libnative-lib.so 重命名为 libnative-lib.mo**
> 4.  把 merge文件夹拷贝至  Linux 环境下执行 gcc merge.c -o merge，生成 merge 可执行文件，然后执行命令 
>  ./merge  libelf_loader.so  libnative-lib.mo  ，然后就会生成加固后的 so ：libnative-lib.so
