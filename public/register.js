document.addEventListener('DOMContentLoaded', function() {
	document.getElementById('regform').addEventListener('submit', register);
});

async function register(e) {
	e.preventDefault();
	const username = document.querySelector('#username').value;
	const password = document.querySelector('#password').value;
	const token = await grecaptcha.execute('6LcbYOMUAAAAADCSJtjfEAaK5kde7pC4Xxrq4q43', { action: 'homepage' });
	let res = await fetch('/api/register', {
		method: 'POST',
		credentials: 'include',
		headers: {
			Accept: 'application/json, */*',
			'Content-type': 'application/json'
		},
		body: JSON.stringify({ username: username, password: password, token: token })
	});
	if(res.redirected) window.location.href = res.url;
	else window.location.href = '/register'
}
