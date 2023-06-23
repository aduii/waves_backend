from django.shortcuts import render

# Create your views here.
from django.http import JsonResponse
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import viewsets,status
from .models import User, Report, Vulnerability
from .serializers import UserSerializer, ReportSerializer, VulnerabilitySerializer
from .scan_scripts import web_server_grabbing
from django.db.models import Max
#--


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    @action(detail=False, methods=['GET'])
    def search(self, request):
        email = request.query_params.get('email', None)
        if email is not None:
            users = User.objects.filter(email=email)
            serializer = UserSerializer(users, many=True)
            return Response(serializer.data)
        else:
            return Response({'error': 'Email parameter is required.'}, status=400)

class ReportViewSet(viewsets.ModelViewSet):
    queryset = Report.objects.all()
    serializer_class = ReportSerializer
    
    @action(detail=False, methods=['GET'])
    def get_reports_by_user_id(self, request):
        user_id = request.query_params.get('user_id')

        if user_id is None:
            return Response({'error': 'Missing user_id parameter'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'error': 'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        reports = Report.objects.filter(user=user)
        serializer = self.get_serializer(reports, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['GET'])
    def get_report_by_id(self, request, pk=None):
        try:
            report = self.get_object()
            serializer = self.get_serializer(report)
            return Response(serializer.data)
        except Report.DoesNotExist:
            return Response({'error': 'Report does not exist'}, status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=['GET'])
    def get_latest_report_id(self, request):
        user_id = request.query_params.get('user_id', None)

        if user_id is None:
            return Response({'error': 'Missing user_id parameter'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'error': 'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        latest_report_id = Report.objects.filter(user=user).aggregate(Max('id')).get('id__max')

        return Response({'latest_report_id': latest_report_id})

    @action(detail=False, methods=['POST'])
    def register_report(self, request):
        data = request.data

        # Obtener los datos del reporte de la solicitud
        name = data.get('name')
        date = data.get('date')
        ip = data.get('ip')
        user_id = data.get('user_id')

        # Validar los datos recibidos
        if not name or not date or not user_id:
            return Response({'error': 'Missing required information'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Obtener el usuario asociado al reporte
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'error': 'Username does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        # Crear el reporte
        report = Report.objects.create(name=name, date=date, ip=ip, user=user)

        # Serializar el reporte creado
        serializer = self.get_serializer(report)

        return Response(serializer.data, status=status.HTTP_201_CREATED)

class VulnerabilityViewSet(viewsets.ModelViewSet):
    queryset = Vulnerability.objects.all()
    serializer_class = VulnerabilitySerializer

    @action(detail=False, methods=['GET'])
    def get_vulnerabilities_by_report_id(self, request):
        report_id = request.query_params.get('report_id', None)
        
        if report_id is not None:
            try:
                report = Report.objects.get(id=report_id)
                vulnerabilities = Vulnerability.objects.filter(report=report)
                serializer = self.get_serializer(vulnerabilities, many=True)
                return Response(serializer.data)
            except Report.DoesNotExist:
                return Response({'error': 'Report does not exist'}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({'error': 'Missing report_id parameter'}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['GET'])
    def web_server_grab(self, request):
        ip = request.query_params.get('ip', None)
        
        if ip is not None:
            result = web_server_grabbing(ip)
            return Response({'result': result})
        
        return Response({'error': 'Missing parameter'}, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['POST'])
    def register_vulnerability(self, request):
        data = request.data

        # Obtener los datos de la vulnerabilidad de la solicitud
        cve_code = data.get('cveCode')
        description = data.get('description')
        exploit = data.get('exploit')
        exploit_link = data.get('exploitLink')
        impact = data.get('impact')
        report_id = data.get('report_id')

        # Validar los datos recibidos
        if not cve_code or not description or not exploit or not exploit_link or not impact or not report_id:
            return Response({'error': 'Missing required information'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Obtener el reporte asociado a la vulnerabilidad
            report = Report.objects.get(id=report_id)
        except Report.DoesNotExist:
            return Response({'error': 'Report does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        # Crear la vulnerabilidad
        vulnerability = Vulnerability.objects.create(cveCode=cve_code, description=description, exploit=exploit, exploitLink=exploit_link, impact=impact, report=report)

        # Serializar la vulnerabilidad creada
        serializer = self.get_serializer(vulnerability)

        return Response(serializer.data, status=status.HTTP_201_CREATED)