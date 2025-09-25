require("dotenv").config();
const SibApiV3Sdk = require("sib-api-v3-sdk");

// Configure Brevo API key
const client = SibApiV3Sdk.ApiClient.instance;
client.authentications["api-key"].apiKey = process.env.BREVO_API_KEY;

const tranEmailApi = new SibApiV3Sdk.TransactionalEmailsApi();

async function testEmail() {
  try {
    const response = await tranEmailApi.sendTransacEmail({
      sender: { email: process.env.SENDER_EMAIL, name: "FunPlusMath Test" },
      to: [{ email: "your_email@gmail.com", name: "Test Recipient" }],
      subject: "Test Email from Brevo",
      htmlContent: "<p>This is a test email sent using Brevo API.</p>",
    });

    console.log("✅ Email sent successfully!");
    console.log(response);

  } catch (err) {
    console.error("❌ Brevo error:");
    if (err.response) {
      console.error(err.response.body);
    } else {
      console.error(err.message);
    }
  }
}

testEmail();
