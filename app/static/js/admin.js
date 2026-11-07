// Admin dashboard charts (Chart.js). Data comes from data-chart attributes.
(function () {
  "use strict";
  if (typeof Chart === "undefined") return;
  var COLORS = { safe: "#198754", suspicious: "#e0a800", phishing: "#c0392b" };

  var line = document.getElementById("scansChart");
  if (line) {
    var d = JSON.parse(line.dataset.chart);
    new Chart(line, {
      type: "bar",
      data: {
        labels: d.labels,
        datasets: [
          { label: "Likely Safe", data: d.safe, backgroundColor: COLORS.safe },
          { label: "Suspicious", data: d.suspicious, backgroundColor: COLORS.suspicious },
          { label: "Likely Phishing", data: d.phishing, backgroundColor: COLORS.phishing }
        ]
      },
      options: {
        responsive: true,
        scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } },
        plugins: { legend: { position: "bottom" } }
      }
    });
  }

  var pie = document.getElementById("breakdownChart");
  if (pie) {
    var p = JSON.parse(pie.dataset.chart);
    new Chart(pie, {
      type: "doughnut",
      data: {
        labels: ["Likely Safe", "Suspicious", "Likely Phishing"],
        datasets: [{ data: [p.safe, p.suspicious, p.phishing],
                     backgroundColor: [COLORS.safe, COLORS.suspicious, COLORS.phishing] }]
      },
      options: { plugins: { legend: { position: "bottom" } }, cutout: "62%" }
    });
  }
})();
