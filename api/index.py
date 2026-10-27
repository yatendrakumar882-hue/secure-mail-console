def choose_smart_replies(subject, body, html_mode):
    text = (
        safe_header(subject, 200) + " " +
        plain_body(body, html_mode)
    ).lower()

    # Quote / pricing templates
    if any(w in text for w in (
        "quote", "quotation", "estimate", "pricing", "price", "cost"
    )):
        return [
            "Yes, please send the quote",
            "Please share the pricing details",
            "I'll review the quote",
        ]

    # SEO / Google ranking templates
    if any(w in text for w in (
        "seo", "ranking", "google", "backlink",
        "keyword", "traffic", "search engine"
    )):
        return [
            "Please share the SEO details",
            "I'm interested in your service",
            "What are the next steps?",
        ]

    # Website service templates
    if any(w in text for w in ("website", "web design", "web development")):
        return [
            "Please share the website details",
            "I'd like to know more",
            "What would you recommend?",
        ]

    # Meetings / appointments
    if any(w in text for w in (
        "meeting", "call", "appointment", "schedule"
    )):
        return [
            "Please share a suitable time",
            "That works for me",
            "Please send the details",
        ]

    # Documents / reports
    if any(w in text for w in ("document", "report", "attachment", "pdf")):
        return [
            "Please send the document",
            "I'll review the details",
            "Please share the information",
        ]

    # General fallback
    return [
        "Yes, please share the details",
        "I'm interested in learning more",
        "What are the next steps?",
    ]


def build_html_email(body, sender_name, sender_email, subject, html_mode):
    if html_mode:
        content = str(body or "")
    else:
        content = (
            '<div style="font-family:Arial,sans-serif;'
            'font-size:14px;font-weight:400;line-height:1.55;'
            'color:#303030;">'
            + html.escape(str(body or "")).replace("\n", "<br>")
            + '</div>'
        )

    replies = choose_smart_replies(subject, body, html_mode)
    buttons = []

    for reply in replies:
        href = html.escape(
            make_reply_link(
                sender_email,
                subject,
                reply,
                quoted_original(
                    sender_name, sender_email, body, html_mode
                ),
            ),
            quote=True,
        )

        buttons.append(
            '<a href="' + href + '" '
            'style="display:inline-block;margin:8px 7px 0 0;'
            'padding:7px 12px;border:1px solid #dadce0;'
            'border-radius:6px;background:#fff;color:#1a73e8;'
            'font-family:Arial,sans-serif;font-size:14px;'
            'font-weight:400;line-height:1.35;'
            'text-decoration:none;">'
            + html.escape(reply)
            + '</a>'
        )

    return (
        '<div style="font-family:Arial,sans-serif;font-weight:400;">'
        + content
        + '<div style="margin-top:14px;padding-top:7px;'
          'border-top:1px solid #eeeeee;">'
        + ''.join(buttons)
        + '</div></div>'
    )
