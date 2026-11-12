puts "Gowin build: starting"
set project_root [file dirname [file normalize [info script]]]
set gprj [file normalize [file join $project_root "ascon128.gprj"]]
puts "Gowin build: open_project $gprj"
open_project $gprj
set_option -include_path [file normalize [file join $project_root ../../../rtl]]
set_option -top_module top_ascon128
puts "Gowin build: run all"
run all
puts "Gowin build: done"
