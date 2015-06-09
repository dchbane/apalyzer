#!/bin/ksh
#
# ea3_draw_pie_chart_2_entries.sh
#
# Input paramters: $1 - first value
#                  $2 - second value
#                  $3 - title
#                  $4 - legend 1
#                  $5 - legend 2
#                  $6 - legend for value 1
#                  $7 - legend for value 2
#                  $8 - output filename
#
# Run like: ./ea3_draw_pie_chart_2_entries.sh f nf "Type of Requests" "Requests" "Type of Requests" "Forms" "Non-Forms" "ea3_forms_pie_chart.html"
#

  BASE_DIR=$(dirname $0)/../

  cat $BASE_DIR/charts/pie_top > $8

  printf "
        ['$4', '$5'],
        ['$6', %d],
        ['$7', %d]
        ]);
       var options = { title: '$3' };" "$1" "$2" >> $8 

  cat $BASE_DIR/charts/pie_bottom >> $8 

