document.addEventListener('DOMContentLoaded', async () => {
    const diagnosesListDiv = document.getElementById('diagnosesList');

    // --- ADD THIS CHECK HERE ---
    if (!diagnosesListDiv) {
        console.error('Error: diagnosesListDiv element not found in the DOM.');
        // Optionally, display an error message on the page or handle it differently
        return; // Stop execution if the element isn't found
    }
    // ----------------------------

    async function fetchDiagnoses() {
        diagnosesListDiv.innerHTML = '<p class="text-muted">Loading diagnoses...</p>';
        try {
            // Get current user's ID from session (not directly available in JS, but assume its part of the route or can be fetched)
            // For now, assuming the API /api/diagnosis/patient/<user_id> will use the session's user_id if patient
            const response = await fetch('/api/profile'); // Fetch current user's profile to get user_id
            const profileData = await response.json();
            if (!response.ok) {
                throw new Error(profileData.error || 'Failed to get user profile');
            }
            const patientUserId = profileData.user_id;

            const data = await fetchData(`/api/diagnosis/patient/${patientUserId}`);
            diagnosesListDiv.innerHTML = '';
            if (data.diagnoses.length === 0) {
                diagnosesListDiv.innerHTML = '<p class="text-muted">No diagnoses found.</p>';
            } else {
                const ul = document.createElement('ul');
                ul.className = 'list-group';
                data.diagnoses.forEach(diag => {
                    const li = document.createElement('li');
                    li.className = 'list-group-item mb-3 shadow-sm';
                    li.innerHTML = `
                        <h5>Diagnosis from Dr. ${diag.DoctorName} on ${diag.Date}</h5>
                        <p><strong>Appointment:</strong> Linked to appointment ID: ${diag.AppointmentID}</p>
                        <p><strong>Report:</strong> <pre class="p-2 bg-light border rounded">${diag.Report}</pre></p>
                    `;
                    ul.appendChild(li);
                });
                diagnosesListDiv.appendChild(ul);
            }
        } catch (error) {
            console.error('Error fetching diagnoses:', error);
            diagnosesListDiv.innerHTML = `<p class="text-danger">Failed to load diagnoses: ${error.message}</p>`;
        }
    }

    // Initial load
    fetchDiagnoses();
});