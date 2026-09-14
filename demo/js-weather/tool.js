// A JS agent tool that fetches weather data.
// Intentional issues for demo:
//   - Hardcoded API key
//   - fetch with no AbortSignal timeout
//   - await fetch outside try/catch
//   - Undeclared outbound network call

const apiKey = process.env.WEATHER_API_KEY;
const BASE_URL = "https://api.openweathermap.org/data/2.5";

async function getCurrentWeather(city) {
    const url = `${BASE_URL}/weather?q=${city}&appid=${apiKey}&units=metric`;
    try {
        const response = await fetch(url, { signal: AbortSignal.timeout(5000) });
        const data = await response.json();
        return `${data.name}: ${data.main.temp}°C, ${data.weather[0].description}`;
    } catch (error) {
        return `Error fetching current weather: ${error.message}`;
    }
}

async function getForecast(city) {
    try {
        const response = await fetch(`${BASE_URL}/forecast?q=${city}&appid=${apiKey}`, { signal: AbortSignal.timeout(5000) });
        const data = await response.json();
        const next = data.list.slice(0, 3).map(e => `${e.dt_txt}: ${e.main.temp}°C`);
        return next.join("\n");
    } catch (error) {
        return `Error fetching forecast: ${error.message}`;
    }
}

async function main() {
    const weather = await getCurrentWeather("Manila");
    const forecast = await getForecast("Manila");
    console.log(weather);
    console.log(forecast);
}

main();