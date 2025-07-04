document.addEventListener('DOMContentLoaded', async () => {
    const logActivityForm = document.getElementById('logActivityForm');
    const activitiesListDiv = document.getElementById('activitiesList');
    const applyFilterBtn = document.getElementById('applyFilterBtn');
    const filterDateFromInput = document.getElementById('filterDateFrom');

    async function fetchActivities() {
        activitiesListDiv.innerHTML = '<p class="text-muted">Loading activities...</p>';
        let url = '/api/activities';
        const dateFrom = filterDateFromInput.value;
        if (dateFrom) {
            url += `?date_from=${dateFrom}`;
        }
        
        try {
            const data = await fetchData(url);
            activitiesListDiv.innerHTML = '';
            if (data.activities.length === 0) {
                activitiesListDiv.innerHTML = '<p class="text-muted">No activities found.</p>';
            } else {
                const ul = document.createElement('ul');
                ul.className = 'list-group';
                data.activities.forEach(activity => {
                    const li = document.createElement('li');
                    li.className = 'list-group-item';
                    li.innerHTML = `
                        <strong>${activity.activity_type}</strong> - ${activity.duration} mins, ${activity.calories_burned || 0} kcal <br>
                        <small class="text-muted">Date: ${activity.date} | Notes: ${activity.notes || 'N/A'}</small>
                    `;
                    ul.appendChild(li);
                });
                activitiesListDiv.appendChild(ul);
            }
        } catch (error) {
            console.error('Error fetching activities:', error);
            activitiesListDiv.innerHTML = `<p class="text-danger">Failed to load activities: ${error.message}</p>`;
        }
    }

    logActivityForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const activity_type = document.getElementById('activityType').value;
        const duration = document.getElementById('duration').value;
        const calories_burned = document.getElementById('caloriesBurned').value;
        const notes = document.getElementById('activityNotes').value;

        try {
            await fetchData('/api/activities', 'POST', {
                activity_type,
                duration: parseInt(duration),
                calories_burned: parseInt(calories_burned) || 0,
                notes
            });
            alert('Activity logged successfully!');
            logActivityForm.reset();
            fetchActivities(); // Refresh the list
        } catch (error) {
            console.error('Error logging activity:', error);
            alert('Failed to log activity: ' + error.message);
        }
    });

    applyFilterBtn.addEventListener('click', fetchActivities);

    // Initial load
    fetchActivities();
});