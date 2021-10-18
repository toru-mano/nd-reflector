cmake_minimum_required(VERSION 3.17)
project(nd-reflector C)

add_executable(ndrd ndrd.c lookup_rib.c)
target_compile_options(ndrd PUBLIC -Wall -Wextra)

install(TARGETS ndrd DESTINATION sbin)
install(PROGRAMS script/ndrd DESTINATION /etc/rc.d)
install(FILES ndrd.8 DESTINATION man/man8)
