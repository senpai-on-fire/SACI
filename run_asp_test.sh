#!/bin/sh

python -m clingo saci/modeling/component.lp saci/modeling/cpv.lp saci/modeling/rover.lp saci/modeling/render.lp -n0 --outf=2 | clingraph --type=digraph --out=render --format=png
