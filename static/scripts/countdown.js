function CountDownTimer(dt, id)
{
    //var end = new Date(dt);

    var _second = 1;
    var _minute = _second * 60;
    var _hour = _minute * 60;
    var _day = _hour * 24;
    var timer;
    tiempo_restante = dt;

    function showRemaining() {
        var countdown_element = document.getElementById(id);
        if (tiempo_restante < 0) {

            clearInterval(timer);
            var titulo = countdown_element.getElementsByClassName('titulo')[0];
            titulo.innerHTML = 'Ya no se pueden realizar cambios en esta sección!';
            titulo.setAttribute('class', titulo.getAttribute('class') + " expired");

            var dias = countdown_element.getElementsByClassName('dias')[0];
            var horas = countdown_element.getElementsByClassName('horas')[0];
            var minutos = countdown_element.getElementsByClassName('minutos')[0];
            var segundos = countdown_element.getElementsByClassName('segundos')[0];
            
            dias.innerHTML = '0';
            horas.innerHTML = '00';
            minutos.innerHTML = '00';
            segundos.innerHTML = '00';

            return;
        }
        var days = Math.floor(tiempo_restante / _day);
        var hours = Math.floor((tiempo_restante % _day) / _hour);
        var minutes = Math.floor((tiempo_restante % _hour) / _minute);
        var seconds = Math.floor((tiempo_restante % _minute) / _second);

        if (hours < 10) {
            hours = '0' + hours;
        }

        if (minutes < 10) {
            minutes = '0' + minutes;
        }

        if (seconds < 10) {
            seconds = '0' + seconds;
        }


        document.getElementById('dias_restantes').innerHTML = days;

        document.getElementById('horas_restantes').innerHTML = hours;
        document.getElementById('minutos_restantes').innerHTML = minutes;
        document.getElementById('segundos_restantes').innerHTML = seconds;

        tiempo_restante -= 1;
    }

    timer = setInterval(showRemaining, 1000);
}

