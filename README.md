# **WINDOWS ROOTKIT**

![userandkernelmode](images/userandkernelmode01.png)

This project is a developpement of a windows rootkit, for training purpose about opaque structures / kernel comprehension
### This project is still in developpement

## What is a rootkit ?

The termrootkit is a "kit" consiting of small and useful programs that allow an attacker to maintain access to "root"
The purpose of a rootkit is to be undetectable and extremely persistant.

## What can you found here ? 

You can found 2 important projects (compiled with visual studio 2022)
- [MyRootKit](MyRootKit/MyRootKit.md) wich is a program that consist of loading the driver with a common and well-known loader using the SCM service*
- [RootKitDriver](RootKitDriver/RootKitDriver.md) *the rootkit driver loaded in kernel mode (paged)*

---
You can found all technical infos about each functions in the directory of each project.

**This project is still in dev, and lot of things just don't work**

