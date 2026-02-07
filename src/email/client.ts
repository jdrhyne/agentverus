/** Email client using Resend SDK */

interface EmailOptions {
	readonly to: string;
	readonly subject: string;
	readonly html: string;
}

/** Send an email via Resend */
export async function sendEmail(options: EmailOptions): Promise<void> {
	const apiKey = process.env.RESEND_API_KEY;
	if (!apiKey || apiKey === "re_...") {
		console.log(`[EMAIL] Would send to ${options.to}: ${options.subject}`);
		return;
	}

	try {
		const response = await fetch("https://api.resend.com/emails", {
			method: "POST",
			headers: {
				Authorization: `Bearer ${apiKey}`,
				"Content-Type": "application/json",
			},
			body: JSON.stringify({
				from: "AgentTrust <trust@agenttrust.dev>",
				to: options.to,
				subject: options.subject,
				html: options.html,
			}),
		});

		if (!response.ok) {
			console.error(`[EMAIL] Failed to send: ${response.status}`);
		}
	} catch (err) {
		console.error("[EMAIL] Error sending email:", err);
	}
}

/** Send certification complete notification */
export async function sendCertificationComplete(
	to: string,
	data: {
		readonly skillName: string;
		readonly score: number;
		readonly badge: string;
		readonly badgeUrl: string;
		readonly certificationId: string;
	},
): Promise<void> {
	const badgeColors: Record<string, string> = {
		certified: "#2ECC40",
		conditional: "#DFB317",
		suspicious: "#FE7D37",
		rejected: "#E05D44",
	};

	const color = badgeColors[data.badge] ?? "#888";

	const html = `
<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: #111; color: #eee;">
	<h1 style="color: #fff;">🛡️ AgentTrust Scan Complete</h1>
	<p>Your skill <strong>"${data.skillName}"</strong> has been scanned.</p>

	<div style="text-align: center; padding: 30px; background: #1a1a1a; border-radius: 12px; margin: 20px 0;">
		<p style="font-size: 48px; font-weight: bold; color: ${color}; margin: 0;">${data.score}/100</p>
		<p style="font-size: 18px; color: ${color}; text-transform: uppercase; letter-spacing: 2px; margin-top: 8px;">${data.badge}</p>
	</div>

	<h2>Embed Your Badge</h2>
	<p>Add this to your README:</p>
	<pre style="background: #1a1a1a; padding: 12px; border-radius: 8px; overflow-x: auto; font-size: 12px;">![AgentTrust](${data.badgeUrl})</pre>

	<p style="color: #888; font-size: 12px; margin-top: 30px;">
		Certification ID: ${data.certificationId}<br>
		<a href="https://agenttrust.dev" style="color: #2ECC40;">agenttrust.dev</a>
	</p>
</body>
</html>`;

	await sendEmail({
		to,
		subject: `AgentTrust: ${data.skillName} scored ${data.score}/100 (${data.badge.toUpperCase()})`,
		html,
	});
}
