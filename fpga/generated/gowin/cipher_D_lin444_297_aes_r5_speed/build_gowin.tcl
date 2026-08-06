puts "Gowin build: starting"
set project_root [file dirname [file normalize [info script]]]
set gprj [file normalize [file join $project_root "cipher_D_lin444_297_aes_r5_speed.gprj"]]
puts "Gowin build: open_project $gprj"
open_project $gprj
puts "Gowin build: run all"
run all
puts "Gowin build: done"
