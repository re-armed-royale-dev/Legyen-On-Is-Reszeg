app.get('/api/events', (req, res) => {
    const mode = (name) => {
        const value = process.env[name] || 'auto';
        return ['auto', 'on', 'off'].includes(value) ? value : 'auto';
    };

    res.set('Access-Control-Allow-Origin', '*');
    res.set('Cache-Control', 'no-store');

    res.json({
        serverTime: new Date().toISOString(),
        events: {
            christmas: {
                mode: mode('CHRISTMAS_EVENT'),
                start: '2026-12-18T00:00:00+01:00',
                end: '2026-12-28T00:00:00+01:00'
            },
            newyear: {
                mode: mode('NEWYEAR_EVENT'),
                start: '2026-12-28T00:00:00+01:00',
                end: '2027-01-05T00:00:00+01:00'
            }
        }
    });
});
