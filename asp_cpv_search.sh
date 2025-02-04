#!/bin/bash

# Takes as arguments additional files containing CPV information,
# e.g., saci-database/saci_db/cpvs/*.lp

python -m clingo saci/modeling/component.lp saci/modeling/cpvsearch.lp saci/modeling/rover.lp "$@" saci/modeling/render.lp -n0 --outf=2 | clingraph --type=digraph --out=render --format=png
