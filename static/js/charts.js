async function loadThreatChart() {

    try {

        const response =
            await fetch("/api/threat-trend");

        const data =
            await response.json();

        const labels =
            data.map(item => item.day);

        const values =
            data.map(item => item.count);

        const canvas =
            document.getElementById("threatChart");

        if (!canvas) {
            console.log("Canvas not found");
            return;
        }

        const ctx =
            canvas.getContext("2d");

        new Chart(ctx, {

            type: "line",

            data: {

                labels: labels,

                datasets: [{

                    label: "Threat Events",

                    data: values,

                    borderColor: "#00ffff",

                    backgroundColor:
                        "rgba(0,255,255,0.2)",

                    fill: true,

                    tension: 0.4,

                    borderWidth: 3

                }]
            },

            options: {

                responsive: true,

                maintainAspectRatio: false,

                plugins: {

                    legend: {

                        labels: {
                            color: "white"
                        }
                    }
                },

                scales: {

                    x: {

                        ticks: {
                            color: "white"
                        }
                    },

                    y: {

                        ticks: {
                            color: "white"
                        }
                    }
                }
            }
        });

    }

    catch(error) {

        console.error(
            "Threat Chart Error:",
            error
        );

    }
}

document.addEventListener(
    "DOMContentLoaded",
    loadThreatChart
);