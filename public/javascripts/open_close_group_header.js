export function setupScrollHandler() {
  document.addEventListener('DOMContentLoaded', function () {
    let global_portada_id = document.getElementById('global_portada_id')
    let portada = document.getElementById('portada')
    let content = document.getElementById('content')
    let imagen = document.getElementById('imagen')

    window.addEventListener('scroll', function () {
      if (window.scrollY > 25) {
        global_portada_id.classList.add('recogido_global_portada')
        portada.classList.add('recogido')
        imagen.classList.add('recogido')
        content.classList.add('recogido')
      } else {
        global_portada_id.classList.remove('recogido_global_portada')
        portada.classList.remove('recogido')
        imagen.classList.remove('recogido')
        content.classList.remove('recogido')
      }
    })
  })
}
