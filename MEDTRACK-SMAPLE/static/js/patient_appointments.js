document.addEventListener('DOMContentLoaded', async () => {
    const requestAppointmentForm = document.getElementById('requestAppointmentForm');
    const doctorSelect = document.getElementById('doctorSelect');
    const appointmentsListDiv = document.getElementById('appointmentsList');

    async function loadDoctors() {
        try {
            const data = await fetchData('/api/doctors/all');
            doctorSelect.innerHTML = '<option value="">-- Select a Doctor --</option>';
            if (data.doctors.length > 0) {
                data.doctors.forEach(doctor => {
                    const option = document.createElement('option');
                    option.value = doctor.user_id; // Use doctor's UserID for the API
                    option.textContent = `Dr. ${doctor.name} (${doctor.specialization})`;
                    doctorSelect.appendChild(option);
                });
            } else {
                doctorSelect.innerHTML = '<option value="">No doctors available.</option>';
            }
        } catch (error) {
            console.error('Error loading doctors:', error);
            doctorSelect.innerHTML = '<option value="">Failed to load doctors.</option>';
            alert('Failed to load doctors: ' + error.message);
        }
    }

    async function fetchAppointments() {
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
                        <strong>Appointment with Dr. ${appt.DoctorName}</strong> <br>
                        Date: ${appt.Date}, Time: ${appt.Time} <br>
                        Status: <span class="badge ${appt.Status === 'Scheduled' ? 'bg-primary' : (appt.Status === 'Completed' ? 'bg-success' : 'bg-danger')}">${appt.Status}</span>
                        ${appt.Status === 'Scheduled' ? `<a href="#" class="btn btn-sm btn-outline-danger float-end ms-2 cancel-btn" data-appointment-id="${appt.appointment_id}">Cancel</a>` : ''}
                    `;
                    ul.appendChild(li);
                });
                appointmentsListDiv.appendChild(ul);
            }
        } catch (error) {
            console.error('Error fetching appointments:', error);
            appointmentsListDiv.innerHTML = `<p class="text-danger">Failed to load appointments: ${error.message}</p>`;
        }
    }

    requestAppointmentForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const doctor_user_id = doctorSelect.value;
        const date = document.getElementById('appointmentDate').value;
        const time = document.getElementById('appointmentTime').value;

        if (!doctor_user_id) {
            alert('Please select a doctor.');
            return;
        }

        try {
            await fetchData('/api/appointments', 'POST', {
                doctor_user_id,
                date,
                time
            });
            alert('Appointment request sent successfully! The doctor will be notified.');
            requestAppointmentForm.reset();
            fetchAppointments(); // Refresh the list
        } catch (error) {
            console.error('Error requesting appointment:', error);
            alert('Failed to request appointment: ' + error.message);
        }
    });

    // Initial loads
    loadDoctors();
    fetchAppointments();
});