document.addEventListener('DOMContentLoaded', async () => {
    const logMetricForm = document.getElementById('logMetricForm');
    const healthMetricsListDiv = document.getElementById('healthMetricsList');
    const applyMetricFilterBtn = document.getElementById('applyMetricFilterBtn');
    const filterMetricTypeInput = document.getElementById('filterMetricType');

    async function fetchHealthMetrics() {
        healthMetricsListDiv.innerHTML = '<p class="text-muted">Loading health metrics...</p>';
        let url = '/api/health-metrics';
        const metricType = filterMetricTypeInput.value;
        if (metricType) {
            url += `?metric_type=${metricType}`;
        }
        
        try {
            const data = await fetchData(url);
            healthMetricsListDiv.innerHTML = '';
            if (data.health_metrics.length === 0) {
                healthMetricsListDiv.innerHTML = '<p class="text-muted">No health metrics found.</p>';
            } else {
                const ul = document.createElement('ul');
                ul.className = 'list-group';
                data.health_metrics.forEach(metric => {
                    const li = document.createElement('li');
                    li.className = 'list-group-item';
                    li.innerHTML = `
                        <strong>${metric.metric_type}</strong>: ${metric.value} ${metric.unit || ''}<br>
                        <small class="text-muted">Date: ${metric.date} | Notes: ${metric.notes || 'N/A'}</small>
                    `;
                    ul.appendChild(li);
                });
                healthMetricsListDiv.appendChild(ul);
            }
        } catch (error) {
            console.error('Error fetching health metrics:', error);
            healthMetricsListDiv.innerHTML = `<p class="text-danger">Failed to load health metrics: ${error.message}</p>`;
        }
    }

    logMetricForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const metric_type = document.getElementById('metricType').value;
        const value = document.getElementById('metricValue').value;
        const unit = document.getElementById('metricUnit').value;
        const notes = document.getElementById('metricNotes').value;

        try {
            await fetchData('/api/health-metrics', 'POST', {
                metric_type,
                value: parseFloat(value),
                unit,
                notes
            });
            alert('Health metric logged successfully!');
            logMetricForm.reset();
            fetchHealthMetrics(); // Refresh the list
        } catch (error) {
            console.error('Error logging metric:', error);
            alert('Failed to log health metric: ' + error.message);
        }
    });

    applyMetricFilterBtn.addEventListener('click', fetchHealthMetrics);

    // Initial load
    fetchHealthMetrics();
});