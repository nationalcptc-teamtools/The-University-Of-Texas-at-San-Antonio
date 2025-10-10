## GoPhish Methodology Kali

Installation & running:
`sudo apt install gophish`
`screen -S gophish` OR run it in `tmux`
`gophish`

Web UI should be on `localhost:3333`.

### Setting up a Campaign

1. Create a sending profile:

Make sure you configure the “SMTP From” to an email address with your sending domain. This domain will be used to perform SPF checks on sent messages.  

- SMTP From: <spoofed email> or the SMTP server
- Host: SMTP host
- Ensure to change the `X-Mailer` header into MS Exchange or something else!

2. Add the email template from our repository
3. Customize variables for the payload and target users:
- `“{{.FirstName}}” “{{.URL}}”`
- For a link: `<a href="{{.URL}}>https://target</a>`
- Add tracking image if you wish

4. Create landing page
- Use one of our templates posted
- Capture submitted data and passwords
- Redirect to the company website OR legitimate login page
- Launch campaign with the configured URL which is the GoPhish server URL that hosts the Landing Page