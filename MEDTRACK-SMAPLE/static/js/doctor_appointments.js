document.addEventListener('DOMContentLoaded', async () => {
    const appointmentsListDiv = document.getElementById('appointmentsList');
    const statusModal = new bootstrap.Modal(document.getElementById('statusModal'));
    const saveStatusButton = document.getElementById('saveStatusButton');
    let currentAppointmentId = null; // To store the ID of the appointment being edited

    async function fetchDoctorAppointments() {
        appointmentsListDiv.innerHTML = '<p class="text-muted">Loading appointments...</p>';
        try {
            const data = await fetchData('/api/appointments');
            appointmentsListDiv.innerHTML = '';
            if (data.appointments.length === 0) {
                appointmentsListDiv.innerHTML = '<p class="text-muted">No appointments found.</p>';
            } else {
                const ul = document.createElement('ul');
                ul.className = 'list-group';
                data.appointments.forEach(appt => {
                    const li = document.createElement('li');
                    li.className = 'list-group-item';
                    li.innerHTML = `
                        <strong>Appointment with ${appt.PatientName}</strong> on ${appt.Date} at ${appt.Time} <br>
                        Status: <span class="badge ${appt.Status === 'Scheduled' ? 'bg-primary' : (appt.Status === 'Completed' ? 'bg-success' : 'bg-danger')}">${appt.Status}</span>
                        <div class="float-end">
                            <button class="btn btn-sm btn-secondary ms-2 status-btn"
                                data-bs-toggle="modal" data-bs-target="#statusModal"
                                data-appointment-id="${appt.appointment_id}"
                                data-patient-name="${appt.PatientName}"
                                data-date="${appt.Date}"
                                data-time="${appt.Time}"
                                data-current-status="${appt.Status}">
                                Update Status
                            </button>
                            ${appt.Status === 'Completed' ? '' : `<a href="/doctor/appointment/${appt.appointment_id}/diagnose" class="btn btn-sm btn-primary ms-2">Diagnose</a>`}
                        </div>
                    `;
                    ul.appendChild(li);
                });
                appointmentsListDiv.appendChild(ul);

                // Add event listeners for status buttons
                document.querySelectorAll('.status-btn').forEach(button => {
                    button.addEventListener('click', (event) => {
                        currentAppointmentId = event.target.dataset.appointmentId;
                        document.getElementById('modalPatientName').textContent = event.target.dataset.patientName;
                        document.getElementById('modalAppointmentDate').textContent = event.target.dataset.date;
                        document.getElementById('modalAppointmentTime').textContent = event.target.dataset.time;
                        document.getElementById('newStatus').value = event.target.dataset.currentStatus;
                    });
                });
            }
        } catch (error) {
            console.error('Error fetching appointments:', error);
            appointmentsListDiv.innerHTML = `<p class="text-danger">Failed to load appointments: ${error.message}</p>`;
        }
    }

    saveStatusButton.addEventListener('click', async () => {
        if (!currentAppointmentId) return;

        const newStatus = document.getElementById('newStatus').value;
        try {
            await fetchData(`/api/appointments/${currentAppointmentId}/status`, 'PUT', { status: newStatus });
            alert('Appointment status updated successfully!');
            statusModal.hide();
            fetchDoctorAppointments(); // Refresh the list
        } catch (error) {
            console.error('Error updating status:', error);
            alert('Failed to update status: ' + error.message);
        }
    });

    // Initial load
    fetchDoctorAppointments();
});