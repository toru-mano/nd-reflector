cmake_minimum_required(VERSION 3.17)
project(nd-reflector C)

add_executable(ndrd ndrd.c lookup_rib.c)
target_compile_options(ndrd PUBLIC -Wall -Wextra)

install(TARGETS ndrd DESTINATION /usr/local/sbin)
install(PROGRAMS script/ndrd DESTINATION /etc/rc.d)
