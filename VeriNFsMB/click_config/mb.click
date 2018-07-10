require("click_verimb")

FromDevice(eth0)
        -> Middlebox(BATCH_SIZE 1000, EFFORT 100, RINGER 0, PM_ALG 2)
        -> ToDevice(eth0);