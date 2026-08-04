#!/bin/bash
# Compare variants on one implementation, robustly enough to trust 5% differences.
#
# Usage:  tools/compare.sh [impl] [repetitions]     (default: avx2, 11)
#
# Two things make the naive "run it and read the number" approach unreliable here.
#
# The cycle counts are nominal TSC ticks, not core clock cycles. A run in which the
# core boosts higher does more work per tick and so reports *fewer* ticks per byte
# for the same code. Taking a minimum across runs therefore does not remove noise,
# it selects whichever run boosted hardest -- which is why this script does not.
#
# And the differences worth seeing are a few percent, while between-run variation is
# larger than that. So: each repetition measures every variant inside one process,
# where the frequency state is shared, and each variant is reported as a ratio to
# present-80 measured in that same process. The ratio is what the frequency cancels
# out of. The absolute column is the median of the per-run medians and is only as
# good as the machine was quiet.
#
# Pinned to one core because the benchmark is single-threaded and migration between
# a P-core and an E-core would swamp everything above.
set -u
IMPL=${1:-avx2}
N=${2:-11}
CPU=${CPU:-2}
BENCH=${BENCH:-./build/bench}

for i in $(seq "$N"); do
  taskset -c "$CPU" "$BENCH" --impl "$IMPL" 2>/dev/null \
    | awk -v im="$IMPL" -v run="$i" '/^[a-z].*\(/{v=$1} $1==im{print run, v, $3}'
done | awk '
  {val[$1" "$2]=$3; vars[$2]=1; runs[$1]=1}
  END{
    for (r in runs) for (v in vars)
      if ((r" "v) in val && (r" present-80") in val)
        printf "%s %.4f %.4f\n", v, val[r" "v]/val[r" present-80"], val[r" "v]
  }' | awk '
  function med(s,   a,n,i,j,t){
    n=split(s,a," ");
    for(i=1;i<n;i++) for(j=1;j<=n-i;j++) if(a[j]+0>a[j+1]+0){t=a[j];a[j]=a[j+1];a[j+1]=t}
    return a[int((n+1)/2)]
  }
  BEGIN{printf "%-30s %8s %9s\n", "variant", "cyc/B", "vs p-80"}
  {rat[$1]=rat[$1]" "$2; abs[$1]=abs[$1]" "$3}
  END{for (v in abs) printf "%-30s %8.2f %8.3fx\n", v, med(abs[v]), med(rat[v])}
' | (read -r h; echo "$h"; sort)
