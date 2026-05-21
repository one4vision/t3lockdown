import TableFilter from '@extension14v/t3lockdown/TableFilter.js';

class Charts {
    constructor() {
        this.chartContainerId = 't3lStatsContainer';
        this.chartDataId = 't3lChartData';
        this.chartData = document.querySelector('#'+this.chartDataId) ?? null;
        this.chartContainer = document.querySelector('#'+this.chartContainerId) ?? null;
        this.buildChart();
    }

    buildChart() {
        if(this.chartContainer && this.chartData) {
            let json = this.chartData.value;
            if(json) {
                json = atob(json);
                json = JSON.parse(json);
                let chart = new CanvasJS.Chart(this.chartContainerId, {
                    animationEnabled: false,
                    data: [{
                        type: "column",
                        cursor: "pointer",
                        explodeOnClick: true,
                        color: "#0078e6",
                        click: this.filterItems,
                        dataPoints: json
                    }]
                });
                chart.render();
            }
        }
    }

    filterItems(e) {
        let label = e.dataPoint.label;
        const [m, y] = label.split(/\s*\/\s*/);
        TableFilter.filterByYearMonth(y,m);
        for(var i=0; i < e.dataSeries.dataPoints.length; i++) {
            e.dataSeries.dataPoints[i].color = (e.dataSeries.dataPoints[i].label === label) ? "#008000" : "#0078e6";
        }
        e.chart.render();
    }

    resetColumnColors() {
        this.buildChart();
    }
}
export default new Charts();