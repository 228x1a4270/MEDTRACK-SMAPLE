document.addEventListener('DOMContentLoaded', async () => {
    const profileForm = document.getElementById('profileForm');
    const nameInput = document.getElementById('name');
    const emailInput = document.getElementById('email');
    const phoneInput = document.getElementById('phone');
    const roleInput = document.getElementById('role');

    const patientFieldsDiv = document.getElementById('patientFields');
    const ageInput = document.getElementById('age');
    const medicalHistoryTextarea = document.getElementById('medicalHistory');

    const doctorFieldsDiv = document.getElementById('doctorFields');
    const specializationInput = document.getElementById('specialization');
    const experienceInput = document.getElementById('experience');

    async function fetchData(url, method = 'GET', data = null) {
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json'
            }
        };
        if (data) {
            options.body = JSON.stringify(data);
        }

        const res = await fetch(url, options);
        if (!res.ok) throw new Error(await res.text());
        return await res.json();
    }

    async function loadUserProfile() {
        try {
            const data = await fetchData('/api/profile');
            nameInput.value = data.name || '';
            emailInput.value = data.email || '';
            phoneInput.value = data.phone || '';
            roleInput.value = data.role || '';

            if (data.role === 'patient') {
                patientFieldsDiv.style.display = 'block';
                doctorFieldsDiv.style.display = 'none';
                ageInput.value = data.age || '';
                medicalHistoryTextarea.value = data.medical_history || '';
            } else if (data.role === 'doctor') {
                doctorFieldsDiv.style.display = 'block';
                patientFieldsDiv.style.display = 'none';
                specializationInput.value = data.specialization || '';
                experienceInput.value = data.experience || '';
            } else {
                patientFieldsDiv.style.display = 'none';
                doctorFieldsDiv.style.display = 'none';
            }
        } catch (error) {
            console.error('Error loading profile:', error);
            alert('Failed to load profile data: ' + error.message);
        }
    }

    profileForm.addEventListener('submit', async (event) => {
        event.preventDefault();

        const dataToUpdate = {
            name: nameInput.value,
            phone: phoneInput.value
        };

        const role = roleInput.value;
        if (role === 'patient') {
            dataToUpdate.age = parseInt(ageInput.value);
            dataToUpdate.medical_history = medicalHistoryTextarea.value;
        } else if (role === 'doctor') {
            dataToUpdate.specialization = specializationInput.value;
            dataToUpdate.experience = parseInt(experienceInput.value);
        }

        try {
            await fetchData('/api/profile', 'PUT', dataToUpdate);
            alert('Profile updated successfully!');
            window.location.reload();
        } catch (error) {
            console.error('Error updating profile:', error);
            alert('Failed to update profile: ' + error.message);
        }
    });

    loadUserProfile();
});
