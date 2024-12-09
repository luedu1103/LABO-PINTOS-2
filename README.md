## Intro
Hi, this is the rustteam, a group in the Operative System course.

![Alt text](https://cdn.discordapp.com/emojis/1184175117840961606.webp?size=96&quality=lossless)

In this repository we will be saving the progress of the labs of this course.

## Set up and building
You need docker to run this project
1. Clone the repository
2. Run this in a command line
``` docker run -it --rm --name pintos --mount type=bind,source="path/to/the/cloned/repository",target=/home/PKUOS/pintos pkuflyingpig/pintos bash ```
3. To run the tests enter to ``` /src/userprog/ ``` and run ``` make check ```
