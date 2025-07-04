document.addEventListener('DOMContentLoaded', async () => {
    const setGoalForm = document.getElementById('setGoalForm');
    const goalsListDiv = document.getElementById('goalsList');

    async function fetchGoals() {
        goalsListDiv.innerHTML = '<p class="text-muted">Loading goals...</p>';
        try {
            const data = await fetchData('/api/goals');
            goalsListDiv.innerHTML = '';
            if (data.goals.length === 0) {
                goalsListDiv.innerHTML = '<p class="text-muted">No active goals found. Set a new one!</p>';
            } else {
                const ul = document.createElement('ul');
                ul.className = 'list-group';
                data.goals.forEach(goal => {
                    const li = document.createElement('li');
                    li.className = 'list-group-item';
                    li.innerHTML = `
                        <strong>${goal.goal_type}</strong>: Target ${goal.target_value}, Current ${goal.current_value}<br>
                        <small class="text-muted">Target Date: ${goal.target_date} | Status: ${goal.status} | Description: ${goal.description || 'N/A'}</small>
                    `;
                    ul.appendChild(li);
                });
                goalsListDiv.appendChild(ul);
            }
        } catch (error) {
            console.error('Error fetching goals:', error);
            goalsListDiv.innerHTML = `<p class="text-danger">Failed to load goals: ${error.message}</p>`;
        }
    }

    setGoalForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const goal_type = document.getElementById('goalType').value;
        const target_value = document.getElementById('targetValue').value;
        const current_value = document.getElementById('currentValue').value;
        const target_date = document.getElementById('targetDate').value;
        const description = document.getElementById('goalDescription').value;

        try {
            await fetchData('/api/goals', 'POST', {
                goal_type,
                target_value: parseFloat(target_value),
                current_value: parseFloat(current_value),
                target_date,
                description
            });
            alert('Goal set successfully!');
            setGoalForm.reset();
            fetchGoals(); // Refresh the list
        } catch (error) {
            console.error('Error setting goal:', error);
            alert('Failed to set goal: ' + error.message);
        }
    });

    // Initial load
    fetchGoals();
});