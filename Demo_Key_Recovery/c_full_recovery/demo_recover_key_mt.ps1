$ErrorActionPreference = "Stop"

$gcc = "C:\MinGW\bin\gcc.exe"
$src = "peel_bruteforce_mt.c"
$exe = ".\peel_bruteforce_mt.exe"

& $gcc -O3 -march=native -Wall -Wextra -std=c11 $src -o $exe
python .\make_demo_candidate_files.py

& $exe recover-key `
  --codebook .\default_codebook.bin `
  --beam 16 `
  --key-beam 3 `
  --stop-stage 1 `
  --coarse-highs 4 `
  --coarse-low-step 16 `
  --coarse-keep 3 `
  --strong-highs 8 `
  --strong-low-step 8 `
  --strong-keep 3 `
  --low-profile 8,17,13,3,2,4,1,1 `
  --high-profile 1,1,1,1,1,1,1,8 `
  --candidate-file 1:demo_candidate_files\stage1.tsv `
  --candidate-file 2:demo_candidate_files\stage2.tsv `
  --candidate-file 3:demo_candidate_files\stage3.tsv `
  --candidate-file 4:demo_candidate_files\stage4.tsv `
  --candidate-file 5:demo_candidate_files\stage5.tsv `
  --candidate-file 6:demo_candidate_files\stage6.tsv `
  --candidate-file 7:demo_candidate_files\stage7.tsv `
  --candidate-file 8:demo_candidate_files\stage8.tsv `
  --threads 16 `
  --progress-ms 500
