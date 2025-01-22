document.addEventListener('DOMContentLoaded', () => {
    const uploadForm = document.getElementById('uploadForm');
    const fileInput = document.getElementById('fileInput');
    const progressContainer = document.getElementById('progressContainer');
    const progressBar = document.getElementById('progress');
    const progressText = document.getElementById('progressText');
    const resultsSection = document.getElementById('resultsSection');
    const errorContainer = document.getElementById('errorContainer');
    const errorMessage = document.getElementById('errorMessage');

    let protocolChartInstance = null;
    let ipChartInstance = null;
    let sizeChartInstance = null;

    uploadForm.addEventListener('submit', async (event) => {
        event.preventDefault();

        resultsSection.style.display = 'none';
        errorContainer.style.display = 'none';
        progressContainer.style.display = 'block';
        progressBar.style.width = '0%';
        progressText.textContent = 'Uploading...';

        const file = fileInput.files[0];
        if (!file) {
            showError('Please select a file before uploading.');
            return;
        }

        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await uploadFile(formData);
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'An unknown error occurred during file analysis.');
            }

            displayResults(data);
        } catch (error) {
            showError(error.message);
        } finally {
            progressContainer.style.display = 'none';
        }
    });

    async function uploadFile(formData) {
        return fetch('/upload', {
            method: 'POST',
            body: formData,
        });
    }

    function displayResults(data) {
        resultsSection.style.display = 'block';

        // Summary
        const summary = `
            <p><strong>Total Packets:</strong> ${data.total_packets}</p>
            <p><strong>Average Packet Size:</strong> ${data.avg_packet_size.toFixed(2)} bytes</p>
            <p><strong>Total Errors:</strong> ${data.errors}</p>
        `;
        document.getElementById('summary').innerHTML = summary;

        // Destroy existing charts if they exist
        if (protocolChartInstance) protocolChartInstance.destroy();
        if (ipChartInstance) ipChartInstance.destroy();
        if (sizeChartInstance) sizeChartInstance.destroy();

        // Protocol Chart
        protocolChartInstance = new Chart(document.getElementById('protocolChart').getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: Object.keys(data.protocols),
                datasets: [{
                    data: Object.values(data.protocols),
                    backgroundColor: ['#ff6384', '#36a2eb', '#cc65fe', '#ffce56'],
                }],
            },
            options: {
                plugins: {
                    title: {
                        display: true,
                        text: 'Protocol Distribution',
                    },
                },
            },
        });

        // IP Chart
        const sortedIPs = Object.entries(data.ip_data).sort((a, b) => b[1] - a[1]).slice(0, 10);
        ipChartInstance = new Chart(document.getElementById('ipChart').getContext('2d'), {
            type: 'bar',
            data: {
                labels: sortedIPs.map(([ip]) => ip),
                datasets: [{
                    label: 'IP Count',
                    data: sortedIPs.map(([, count]) => count),
                    backgroundColor: '#36a2eb',
                }],
            },
            options: {
                plugins: {
                    title: {
                        display: true,
                        text: 'Top 10 IPs by Traffic Volume',
                    },
                },
                scales: {
                    x: {
                        ticks: { color: '#ffffff' },
                    },
                    y: {
                        beginAtZero: true,
                        ticks: { color: '#ffffff' },
                    },
                },
            },
        });

        // Packet Size Chart
        sizeChartInstance = new Chart(document.getElementById('sizeChart').getContext('2d'), {
            type: 'line',
            data: {
                labels: data.packet_sizes.map((_, i) => i + 1),
                datasets: [{
                    label: 'Packet Sizes',
                    data: data.packet_sizes,
                    borderColor: '#ff6384',
                    backgroundColor: 'rgba(255,99,132,0.2)',
                    fill: true,
                }],
            },
            options: {
                plugins: {
                    title: {
                        display: true,
                        text: 'Packet Sizes Over Time',
                    },
                },
                scales: {
                    x: {
                        ticks: { color: '#ffffff' },
                    },
                    y: {
                        beginAtZero: true,
                        ticks: { color: '#ffffff' },
                    },
                },
            },
        });
    }

    function showError(message) {
        errorContainer.style.display = 'block';
        errorMessage.textContent = message;
    }
});
