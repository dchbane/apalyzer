#!/bin/ksh
#
# ea3_draw_3bars_chart.sh
#
# Input parameters: $1 - input file
#                   $2 - x legend
#                   $3 - y1 legend
#                   $4 - y2 legend
#                   $5 - y3 legend
#                   $6 - title
#                   $7 - output file

   
   BASE_DIR=$(dirname $0)/../

   cat $BASE_DIR/charts/3bars_top > $7

   printf "       ['$2', '$3', '$4', '$5']\n" >> $7 

   awk '{ print ",", $0 }' $1 >> $7

   printf "     ]);
        var options = {
          chart: { title: '$6' } };\n"  >> $7 

   cat $BASE_DIR/charts/3bars_bottom >> $7 

