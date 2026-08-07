puts "Gowin build: starting"
set project_root [file dirname [file normalize [info script]]]
set gprj [file normalize [file join $project_root "aes_lin444_0_8_15_r4_speed.gprj"]]
puts "Gowin build: open_project $gprj"
open_project $gprj
set_option -top_module aes_lin444_0_8_15_r4_speed_gowin_top
puts "Gowin build: run all"
run all
puts "Gowin build: done"
