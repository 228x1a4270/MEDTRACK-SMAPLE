document.addEventListener('DOMContentLoaded', async () => {
    const patientsListDiv = document.getElementById('patientsList');

    async function fetchMyPatients() {
        patientsListDiv.innerHTML = '<p class="text-muted">Loading patients...</p>';
        try {
            const data = await fetchData('/api/doctors/my_patients');
            patientsListDiv.innerHTML = '';
            if (data.patients.length === 0) {
                patientsListDiv.innerHTML = '<p class="text-muted">You currently have no patients assigned.</p>';
            } else {
                const ul = document.createElement('ul');
                ul.className = 'list-group';
                data.patients.forEach(patient => {
                    const li = document.createElement('li');
                    li.className = 'list-group-item';
                    li.innerHTML = `
                        <strong>${patient.name}</strong> (${patient.email}) - Age: ${patient.age || 'N/A'}
                        <a href="/doctor/patient/${patient.user_id}/details" class="btn btn-sm btn-primary float-end ms-2">View Details</a>
                    `;
                    ul.appendChild(li);
                });
                patientsListDiv.appendChild(ul);
            }
        } catch (error) {
            console.error('Error fetching patients:', error);
            patientsListDiv.innerHTML = `<p class="text-danger">Failed to load patients: ${error.message}</p>`;
        }
    }

    // Initial load
    fetchMyPatients();
});