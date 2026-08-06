puts "Gowin build: starting"
set project_root [file dirname [file normalize [info script]]]
set gprj [file normalize [file join $project_root "present_80_r16_speed.gprj"]]
puts "Gowin build: open_project $gprj"
open_project $gprj
set_option -top_module present_80_r16_speed_gowin_top
puts "Gowin build: run all"
run all
puts "Gowin build: done"
