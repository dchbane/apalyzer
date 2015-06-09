#!/bin/ksh
#
# ea3_draw_bar_chart.sh
#
# Input parameters: $1 - input file
#                   $2 - x legend
#                   $3 - y legend
#                   $4 - title
#                   $5 - output file

   cat ./charts/bar_top > $5 

   printf "       ['$2', '$3']\n" >> $5 

   awk '{ print ",", $0 }' $1 >> $5

   printf "     ]);
        var options = {
          chart: { title: '$4' } };\n"  >> $5 

   cat ./charts/bar_bottom >> $5 

