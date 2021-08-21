cmake_minimum_required(VERSION 3.17)
project(ndp-reflector C)

add_executable(ndprd ndprd.c lookup_rib.c)
target_compile_options(ndprd PUBLIC -Wall -Wextra)

install(TARGETS ndprd DESTINATION /usr/local/sbin)
install(PROGRAMS script/ndprd DESTINATION /etc/rc.d)
