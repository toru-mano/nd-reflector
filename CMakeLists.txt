cmake_minimum_required(VERSION 3.17)
project(ndp-reflector C)

add_compile_options(-Wall -Wextra)
add_executable(ndprd ndprd.c)

install(TARGETS ndprd DESTINATION /usr/local/sbin)
install(PROGRAMS script/ndprd DESTINATION /etc/rc.d)
