ARG RUNTIME_IMAGE
FROM ${RUNTIME_IMAGE}
USER root
COPY sddm-lab-image.sh /opt/fplogin-lab/image.sh
RUN bash /opt/fplogin-lab/image.sh
COPY sddm-lab-container.py /opt/fplogin-lab/container.py
COPY collect_sddm_lab.py /usr/local/lib/fplogin-lab/collect_sddm_lab.py
COPY sddm-lab-guest.py /usr/local/sbin/fplogin-lab
RUN chmod 755 /usr/local/sbin/fplogin-lab
ENTRYPOINT ["python3", "/opt/fplogin-lab/container.py"]
CMD ["boot"]
